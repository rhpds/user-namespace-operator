from __future__ import annotations
from collections.abc import Mapping
from typing import Any, List

import asyncio
import kubernetes_asyncio
from kubernetes_asyncio.client import V1Namespace

from kopf._core.actions import loggers

from templating import process_template
from usernamespaceoperator import UserNamespaceOperator
from group import Group
from user import User
from usernamespaceconfig import UserNamespaceConfig, UserNamespaceRoleBinding, UserNamespaceTemplate

from k8s_api_group import K8sApiGroup

class UserNamespace:
    instances = {}
    lock = asyncio.Lock()

    @classmethod
    async def create(cls,
        name: str,
        user: User,
        user_namespace_config: UserNamespaceConfig,
        description: str|None = None,
        display_name: str|None = None,
    ) -> UserNamespace:
        definition = {
            'apiVersion': UserNamespaceOperator.operator_api_version,
            'kind': 'UserNamespace',
            'metadata': {
                'name': name,
                'labels': {
                    UserNamespaceOperator.operator_domain + '/config': user_namespace_config.name,
                    UserNamespaceOperator.operator_domain + '/user-uid': user.uid,
                },
                'ownerReferences': [{
                    "controller": True,
                    **user.reference
                }]
            },
            'spec': {
                'config': user_namespace_config.reference,
                'user': user.reference,
            }
        }

        if description is not None:
            definition['spec']['description'] = description

        if display_name is not None:
            definition['spec']['displayName'] = display_name

        definition = await UserNamespaceOperator.custom_objects_api.create_cluster_custom_object(
            group = UserNamespaceOperator.operator_domain,
            plural = 'usernamespaces',
            version = UserNamespaceOperator.operator_version,
            body = definition,
        )
        return await cls.register_definition(definition=definition)

    @classmethod
    async def get(cls, name: str) -> UserNamespace|None:
        async with cls.lock:
            if name in cls.instances:
                return cls.instances[name]
            try:
                definition = await UserNamespaceOperator.custom_objects_api.get_cluster_custom_object(
                    UserNamespaceOperator.operator_domain, UserNamespaceOperator.operator_version, 'usernamespaces', name
                )
                return cls.register_definition(definition)
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status == 404:
                    return None
                else:
                    raise

    @classmethod
    def get_user_namespaces_for_config(cls,
        user_namespace_config: UserNamespaceConfig,
    ) -> List[UserNamespace]:
        return [
            user_namespace for user_namespace in cls.instances.values()
            if user_namespace.config_name == user_namespace_config.name
        ]

    @classmethod
    def get_user_namespaces_for_user(cls,
        user: User,
    ) -> List[UserNamespace]:
        return [
            user_namespace for user_namespace in cls.instances.values()
            if user_namespace.user_uid == user.uid
        ]

    @classmethod
    def get_user_namespaces_for_config_and_user(cls,
        user: User,
        user_namespace_config: UserNamespaceConfig,
    ):
        return [
            user_namespace for user_namespace in cls.instances.values()
            if user_namespace.config_name == user_namespace_config.name and user_namespace.user_uid == user.uid
        ]

    @classmethod
    async def preload(cls) -> None:
        _continue = None
        while True:
            user_namespace_list = await UserNamespaceOperator.custom_objects_api.list_cluster_custom_object(
                group = UserNamespaceOperator.operator_domain,
                plural = 'usernamespaces',
                version = UserNamespaceOperator.operator_version,
                _continue = _continue,
                limit = 50,
            )
            for definition in user_namespace_list.get('items', []):
                await cls.register_definition(definition)
            _continue = user_namespace_list['metadata'].get('continue')
            if not _continue:
                break

    @classmethod
    async def register(cls,
        name: str,
        spec: Mapping[str, Any],
        status: Mapping[str, Any],
        uid: str,
    ) -> UserNamespace:
        async with cls.lock:
            instance = cls.instances.get(name)
            if instance:
                instance.refresh(spec=spec, status=status, uid=uid)
            else:
                instance = cls(name=name, spec=spec, status=status, uid=uid)
                cls.instances[name] = instance
            return instance

    @classmethod
    async def register_definition(cls,
        definition: Mapping[str, Any],
    ) -> UserNamespace:
        return await cls.register(
            name = definition['metadata']['name'],
            spec = definition['spec'],
            status = definition.get('status'),
            uid = definition['metadata']['uid'],
        )

    @classmethod
    def unregister(cls, name: str) -> UserNamespace|None:
        return cls.instances.pop(name, None)

    @classmethod
    async def try_create(cls,
        name: str,
        logger: loggers.ObjectLogger,
        user: User,
        user_namespace_config: UserNamespaceConfig,
        description: str|None = None,
        display_name: str|None = None,
    ) -> UserNamespace|None:
        # Get namespace, waiting for namespace deletion to complete if already initiated 
        try:
            while True:
                namespace = await UserNamespaceOperator.core_v1_api.read_namespace(name)
                if namespace.metadata.deletion_timestamp:
                    logger.info(f"Waiting for deletion of namespace {name} to complete")
                    await asyncio.sleep(2)
                    continue
                else:
                    break
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            # 404 error is normal, just means namespace we are trying to create does not exist yet
            if e.status == 404:
                namespace = None
            else:
                raise

        # Check requester annotation on existing namespace
        if namespace and (
            not namespace.metadata.annotations or
            namespace.metadata.annotations.get('openshift.io/requester') != user.name
        ):
            return None

        # Check user-namespace-operator has admin access to existing namespace
        if namespace and not UserNamespaceOperator.operator_cluster_admin:
            try:
                admin_role_binding = await UserNamespaceOperator.rbac_authorization_v1_api.read_namespaced_role_binding(
                    name = 'admin',
                    namespace = namespace.metadata.name
                )
                if len(admin_role_binding.subjects) < 1:
                    return
                # Check the subject for the admin rolebinding
                if admin_role_binding.subjects[0].kind == 'ServiceAccount':
                    if admin_role_binding.subjects[0].name != UserNamespaceOperator.operator_service_account_name \
                    or admin_role_binding.subjects[0].namespace != UserNamespaceOperator.operator_namespace:
                        return
                # Odd bug? When a service account creates a project request the namespace creates an
                # admin rolebinding with kind "User"
                if admin_role_binding.subjects[0].kind == 'User':
                    if admin_role_binding.subjects[0].name != f"system:serviceaccount:{UserNamespaceOperator.operator_namespace}:{UserNamespaceOperator.operator_service_account_name}":
                        return
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status == 404 or e.status == 403:
                    return
                else:
                    raise

        # Try to create the UserNamespace object, accepting 409 conflict as a
        # normal failure to create.
        try:
            user_namespace = await cls.create(
                description=description,
                display_name=display_name,
                name=name,
                user=user,
                user_namespace_config=user_namespace_config,
            )
            if namespace:
                logger.info(f"Autocreated {user_namespace} for {user} to manage existing namespace")
            else:
                logger.info(f"Autocreated {user_namespace} for {user}")
            return user_namespace
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status == 409:
                return None
            else:
                raise

    def __init__(self,
        name: str,
        spec: Mapping[str, Any],
        status: Mapping[str, Any],
        uid: str,
        **_
    ) -> None:
        self.name = name
        self.spec = spec
        self.status = status or {}
        self.uid = uid

    def __str__(self) -> str:
        return f"UserNamespace {self.name}"

    @property
    def config_name(self) -> str:
        return self.spec.get('config', {}).get('name', 'default')

    @property
    def description(self) -> str|None:
        return self.spec.get('description')

    @property
    def display_name(self) -> str|None:
        return self.spec.get('displayName')

    @property
    def managed_resources(self) -> List[Any]:
        return self.status.get('managedResources', [])

    @property
    def reference(self) -> Mapping[str, str]:
        return {
            "apiVersion": UserNamespaceOperator.operator_api_version,
            "kind": 'UserNamespace',
            "name": self.name,
            "uid": self.uid,
        }

    @property
    def user_name(self) -> str:
        return self.user_reference['name']

    @property
    def user_reference(self) -> Mapping[str, str]:
        return self.spec['user']

    @property
    def user_uid(self) -> str:
        return self.user_reference['uid']

    def refresh(self,
        spec: Mapping[str, Any],
        status: Mapping[str, Any],
        uid: str,
    ) -> None:
        self.spec = spec
        self.status = status or {}
        self.uid = uid

    def refresh_from_definition(self,
        definition: Mapping[str, Any],
    ) -> None:
        self.spec = definition['spec']
        self.status = definition.get('status', {})
        self.uid = definition['metadata']['uid']

    async def check_update_namespace(self,
        description: description,
        display_name: display_name,
        logger: loggers.ObjectLogger,
        namespace: V1Namespace,
        user: User,
    ) -> None:
        namespace_name = namespace.metadata.name
        updated = False

        # FIXME - Support udate description and display name with project api

        if not namespace.metadata.annotations:
            logger.info('setting namespace annotations')
            namespace.metadata.annotations = {
                'openshift.io/description': description,
                'openshift.io/displayName': display_name,
                'openshift.io/requester': user.name,
            }
            updated = True
        else:
            if description != namespace.metadata.annotations.get('openshift.io/description', ''):
                logger.info('setting namespace description annotation')
                namespace.metadata.annotations['openshift.io/description'] = description
                updated = True
            if display_name != namespace.metadata.annotations.get('openshift.io/display-name', ''):
                logger.info('setting namespace display-name annotation')
                namespace.metadata.annotations['openshift.io/display-name'] = display_name
                updated = True
            if user.name != namespace.metadata.annotations.get('openshift.io/requester', ''):
                logger.info('setting namespace requester annotation')
                namespace.metadata.annotations['openshift.io/requester'] = user.name
                updated = True

        if not namespace.metadata.labels:
            logger.info('setting namespace user-uid label')
            namespace.metadata.labels = {
                UserNamespaceOperator.operator_domain + '/user-uid': user.uid
            }
            updated = True
        elif user.uid != namespace.metadata.labels.get(UserNamespaceOperator.operator_domain + '/user-uid', ''):
            logger.info('setting namespace user-uid label')
            namespace.metadata.labels[UserNamespaceOperator.operator_domain + '/user-uid'] = user.uid
            updated = True

        if not namespace.metadata.owner_references:
            logger.info('setting namespace owner metadata')
            namespace.metadata.owner_references = [{
                "controller": True,
                **self.reference
            }]
            updated = True

        if updated:
            if UserNamespaceOperator.operator_cluster_admin:
                await UserNamespaceOperator.core_v1_api.replace_namespace(namespace_name, namespace)
            else:
                # Translate to project API
                project = UserNamespaceOperator.api_client.sanitize_for_serialization(namespace)
                project['apiVersion'] = 'project.openshift.io/v1'
                UserNamespaceOperator.custom_objects_api.replace_cluster_custom_object(
                    body=project,
                    group='project.openshift.io',
                    name=namespace_name,
                    plural='projects',
                    version='v1',
                )

    async def create_namespace(self,
        description: description,
        display_name: display_name,
        logger: loggers.ObjectLogger,
        user: User,
    ) -> None:
        if UserNamespaceOperator.operator_cluster_admin:
            await UserNamespaceOperator.core_v1_api.create_namespace(
                kubernetes_asyncio.client.V1Namespace(
                    metadata = kubernetes_asyncio.client.V1ObjectMeta(
                        annotations = {
                            'openshift.io/description': description,
                            'openshift.io/display-name': display_name,
                            'openshift.io/requester': user.name,
                        },
                        labels = {
                            f"{UserNamespaceOperator.operator_domain}/user-uid": user.uid
                        },
                        owner_references = [
                            kubernetes_asyncio.client.V1OwnerReference(
                                api_version = UserNamespaceOperator.operator_api_version,
                                controller = True,
                                kind = 'UserNamespace',
                                name = self.name,
                                uid = self.uid,
                            )
                        ],
                        name = self.name,
                    )
                )
            )
            # Create admin role binding for operator to ensure management can
            # continue if cluster-admin privileges are ever removed.
            await UserNamespaceOperator.rbac_authorization_v1_api.create_namespaced_role_binding(
                self.name,
                kubernetes_asyncio.client.V1RoleBinding(
                    metadata = kubernetes_asyncio.client.V1ObjectMeta(
                        name = 'admin',
                    ),
                    role_ref = kubernetes_asyncio.client.V1RoleRef(
                        api_group = 'rbac.authorization.k8s.io',
                        kind = 'ClusterRole',
                        name = 'admin',

                    ),
                    subjects = [
                        kubernetes_asyncio.client.RbacV1Subject(
                            kind = 'ServiceAccount',
                            name = UserNamespaceOperator.operator_service_account_name,
                            namespace = UserNamespaceOperator.operator_namespace,
                        )
                    ],
                )
            )

        else:
            # Create using a project request so that the operator will be made an
            # administrator.
            project_request = await UserNamespaceOperator.custom_objects_api.create_cluster_custom_object(
                group = 'project.openshift.io',
                plural = 'projectrequests',
                version = 'v1',
                body = {
                    'apiVersion': 'project.openshift.io/v1',
                    'kind': 'ProjectRequest',
                    'metadata': {
                        'name': self.name,
                    },
                    'description': description,
                    'displayName': display_name,
                }
            )

            while True:
                try:
                    namespace = await UserNamespaceOperator.core_v1_api.read_namespace(self.name)
                    logger.info(f"Namespace {self.name} created")
                    namespace.metadata.annotations['openshift.io/requester'] = user.name
                    namespace.metadata.labels = {
                        UserNamespaceOperator.operator_domain + '/user-uid': user.uid
                    }
                    namespace.metadata.owner_references = [
                        kubernetes_asyncio.client.V1OwnerReference(
                            api_version = UserNamespaceOperator.operator_api_version,
                            controller = True,
                            kind = 'UserNamespace',
                            name = self.name,
                            uid = self.uid,
                        )
                    ]
                    await UserNamespaceOperator.core_v1_api.replace_namespace(namespace.metadata.name, namespace)
                    break
                except kubernetes_asyncio.client.exceptions.ApiException as e:
                    if e.status != 404 and e.status != 409:
                        raise

    async def delete(self,
        logger: loggers.ObjectLogger,
    ) -> None:
        try:
            await UserNamespaceOperator.custom_objects_api.delete_cluster_custom_object(
                group = UserNamespaceOperator.operator_domain,
                name = self.name,
                plural = 'usernamespaces',
                version = UserNamespaceOperator.operator_version,
            )
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status != 404:
                raise

    async def get_config(self) -> UserNamespaceConfig|None:
        if self.config_name:
            return await UserNamespaceConfig.get(self.config_name)
        else:
            return None

    async def get_user_and_manage(self,
        logger: loggers.ObjectLogger,
    ) -> None:
        try:
            user = await User.get(self.user_name)
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status == 404:
                logger.info("Deleting %s after user %s not found", self, self.user_name)
                await self.delete(logger=logger)
                return
            else:
                raise
        async with user.lock:
            await self.manage(logger=logger, user=user)

    async def manage(self,
        logger: loggers.ObjectLogger,
        user: User|None = None
    ) -> None:
        config = await self.get_config()
        groups = Group.get_groups_with_user(user.name)
        if not config:
            raise kopf.TemporaryError(
                f"UserNamespaceConfig {self.config_name} not found",
                delay = 60
            )
        await self.manage_namespace(logger=logger, config=config, user=user, groups=groups)
        await self.manage_resources(logger=logger, config=config, user=user, groups=groups)

    async def manage_core_resource(self,
        definition: Mapping[str, Any],
    ) -> Any:
        kind = definition['kind']
        resource_name = definition['metadata']['name']
        namespace = definition['metadata'].get('namespace', None)
        create_namespaced = 'create_namespaced_' + inflection.underscore(kind)
        create_cluster = 'create_' + inflection.underscore(kind)
        relpace_namespaced = 'replace_namespaced_' + inflection.underscore(kind)
        replace_cluster = 'replace_' + inflection.underscore(kind)
        try:
            if hasattr(UserNamespaceOperator.core_v1_api, create_namespaced):
                method = getattr(UserNamespaceOperator.core_v1_api, create_namespaced)
                return await method(self.name, definition)
            else:
                method = getattr(UserNamespaceOperator.core_v1_api, create_cluster)
                return await method(definition)
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        if hasattr(UserNamespaceOperator.core_v1_api, replace_namespaced):
            method = getattr(UserNamespaceOperator.core_v1_api, replace_namespaced)
            return await method(self.name, resource_name, definition)
        else:
            method = getattr(UserNamespaceOperator.core_v1_api, replace_cluster)
            return await method(resource_name, definition)

    async def manage_custom_resource(self,
        definition: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        resource_name = definition['metadata']['name']
        api_group_version = definition['apiVersion']
        api_group = await K8sApiGroup.get(api_group_version)
        if not api_group:
            raise kopf.TemporaryError(
                f"Unable to find information about apiVersion {api_group_version}",
                delay = 60
            )

        kind = definition['kind']
        api_resource = api_group.get_resource(kind = kind)
        if not api_resource:
            raise kopf.TemporaryError(
                f"Unable to find resource kind {kind} in apiVersion {api_group_version}",
                delay = 60
            )

        try:
            if api_resource.namespaced:
                return await UserNamespaceOperator.custom_objects_api.create_namespaced_custom_object(
                    body=definition,
                    group=api_group.name,
                    namespace=self.name,
                    plural=api_resource.plural,
                    version=api_group.version,
                )
            else:
                return await UserNamespaceOperator.custom_objects_api.create_cluster_custom_object(
                    body=definition,
                    group=api_group.name,
                    plural=api_resource.plural,
                    version=api_group.version,
                )
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        if api_resource.namespaced:
            return await UserNamespaceOperator.custom_objects_api.replace_namespaced_custom_object(
                body=definition,
                group=api_group.name,
                name=resource_name,
                namespace=self.name,
                plural=api_resource.plural,
                version=api_group.version,
            )
        else:
            return await UserNamespaceOperator.custom_objects_api.replace_cluster_custom_object(
                body=definition,
                group=api_group.name,
                name=resource_name,
                plural=api_resource.plural,
                version=api_group.version,
            )

    async def manage_namespace(self,
        config: UserNamespaceConfig,
        logger: loggers.ObjectLogger,
        groups: List[Group],
        user: User,
    ) -> None:
        template_variables = {
            "groups": groups,
            "group_names": [group.name for group in groups],
            "user": user,
            "user_name": user.name,
        }

        description = process_template(
            config.description if config.description is not None  else
            self.description if self.description is not None else
            "User namespace for {user.name}",
            template_variables
        )

        display_name = process_template(
            config.display_name if config.display_name is not None else
            self.display_name if self.display_name is not None else
            "User namespace for {user.name}",
            template_variables
        )

        namespace = None
        try:
            namespace = await UserNamespaceOperator.core_v1_api.read_namespace(self.name)
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status != 404:
                raise

        if namespace:
            await self.check_update_namespace(description=description, display_name=display_name, logger=logger, namespace=namespace, user=user)
        else:
            await self.create_namespace(description=description, display_name=display_name, logger=logger, user=user)

    async def manage_resource(self,
        definition: Mapping[str, Any],
    ) -> Any:
        if '/' in definition['apiVersion']:
            return await self.manage_custom_resource(definition)
        else:
            return await self.manage_core_resource(definition)

    async def manage_resources(self,
        config: UserNamespaceConfig,
        logger: loggers.ObjectLogger,
        user: User,
        groups: List[Group],
    ) -> None:
        resource_references = []
        if self.config_name:
            for template in config.templates:
                resource_references.extend(
                    await self.manage_template_resources(
                        logger=logger,
                        template=template,
                        user=user,
                        groups=groups,
                    )
                )

            for role_binding in config.role_bindings:
                if role_binding.check_condition(user=user, groups=groups):
                    resource_references.append(
                        await self.manage_role_binding(
                            logger=logger,
                            role_binding=role_binding,
                            user=user,
                        )
                    )

        for reference in self.managed_resources:
            if reference not in resource_references:
                await self.remove_resource(logger=logger, resource_reference=reference)

        definition = await UserNamespaceOperator.custom_objects_api.patch_cluster_custom_object_status(
            group = UserNamespaceOperator.operator_domain,
            name = self.name,
            plural = 'usernamespaces',
            version = UserNamespaceOperator.operator_version,
            _content_type = 'application/merge-patch+json',
            body = {
                "status": {
                    "managedResources": resource_references,
                }
            }
        )
        self.refresh_from_definition(definition=definition)

    async def manage_role_binding(self,
        logger: loggers.ObjectLogger,
        role_binding: UserNamespaceRoleBinding,
        user: User,
    ) -> Mapping[str, str]:
        role_binding_name = f"{role_binding.role_name}:{user.name}"
        role_binding = await self.manage_resource({
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {
                "name": role_binding_name,
                "namespace": self.name,
            },
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": role_binding.role_name,
            },
            "subjects": [{
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "User",
                "name": user.name,
            }],
        })
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "name": role_binding_name,
            "namespace": self.name,
        }

    async def manage_template_resources(self,
        logger: loggers.ObjectLogger,
        template: UserNamespaceTemplate,
        user: User,
        groups: List[Group],
    ) -> List[Mapping[str, str]]:
        template_variables = {
            "groups": groups,
            "group_names": [group.name for group in groups],
            "user": user,
            "user_name": user.name,
        }

        template_resource = await UserNamespaceOperator.custom_objects_api.get_namespaced_custom_object(
            group='template.openshift.io',
            namespace=template.namespace,
            name=template.name,
            plural='templates',
            version='v1',
        )

        for parameter in template_resource.get('parameters', []):
            if parameter['name'] == 'PROJECT_NAME':
                parameter['value'] = self.name
            elif parameter['name'] == 'PROJECT_ADMIN_USER':
                parameter['value'] = self.user_name
            elif parameter['name'] in template.parameter_values:
                parameter['value'] = process_template(
                    template.parameter_values[parameter['name']],
                    template_variables,
                )

        processed_template = await UserNamespaceOperator.custom_objects_api.create_namespaced_custom_object(
            body=template_resource,
            group='template.openshift.io',
            namespace=template.namespace,
            plural='processedtemplates',
            version='v1',
        )

        resource_references = []
        for resource_definition in processed_template.get('objects', []):
            definition = await self.manage_resource(resource_definition)
            if isinstance(definition, dict):
                reference = {
                    "apiVersion": definition['apiVersion'],
                    "kind": definition['kind'],
                    "name": definition['metadata']['name'],
                }
                if definition['metadata'].get('namespace'):
                    reference['namespace'] = definition['metadata']['namespace']
            else:
                reference = {
                    "apiVersion": definition.api_version,
                    "kind": definition.kind,
                    "name": definition.metadata.name,
                }
                if definition.metadata.namespace:
                    reference['namespace'] = definition.metadata.namespace
            resource_references.append(reference)
        return resource_references

    async def remove_resource(self,
        logger: loggers.ObjectLogger,
        resource_reference: Mapping[str, str],
    ):
        try:
            if '/' in resource_reference['apiVersion']:
                return await self.remove_custom_resource(
                    logger=logger,
                    resource_reference=resource_reference,
                )
            else:
                return await self.remove_core_resource(
                    logger=logger,
                    resource_reference=resource_reference,
                )
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status == 404:
                return None
            else:
                raise

    async def remove_core_resource(self,
        logger: loggers.ObjectLogger,
        resource_reference: Mapping[str, str],
    ):
        kind = resource_reference['kind']
        resource_name = resource_reference['name']
        resource_namespace = resource_reference.get('namespace', None)
        if resource_namespace:
            logger.info("Removing %s %s from %s", kind, resource_name, resource_namespace)
            method = getattr(UserNamespaceOperator.core_v1_api, f"delete_namespaced_{inflection.underscore(kind)}")
            return await method(resource_name, resource_namespace)
        else:
            logger.info("Removing %s %s", kind, resource_name)
            method = getattr(UserNamespaceOperator.core_v1_api, f"delete_{inflection.underscore(kind)}")
            return await method(resource_name)

    async def remove_custom_resource(self,
        logger: loggers.ObjectLogger,
        resource_reference: Mapping[str, str],
    ):
        kind = resource_reference['kind']
        resource_name = resource_reference['name']
        resource_namespace = resource_reference['namespace']
        api_group_version = resource_reference['apiVersion']
        api_group = await K8sApiGroup.get(api_group_version)
        if not api_group:
            raise kopf.TemporaryError(
                f"Unable to find information about apiVersion {api_group_version}",
                delay = 60
            )

        api_resource = api_group.get_resource(kind = kind)
        if not api_resource:
            raise kopf.TemporaryError(
                f"Unable to find resource kind {kind} in apiVersion {api_group_version}",
                delay = 60
            )

        if api_resource.namespaced:
            logger.info(
                "Removing %s %s %s from %s",
                api_group_version, kind, resource_name, resource_namespace,
            )
            return await UserNamespaceOperator.custom_objects_api.delete_namespaced_custom_object(
                api_group.name, api_group.version, resource_namespace or self.name, api_resource.plural, resource_name
            )
        else:
            logger.info(
                "Removing %s %s %s",
                api_group_version, kind, resource_name,
            )
            return await UserNamespaceOperator.custom_objects_api.delete_cluster_custom_object(
                api_group.name, api_group.version, api_resource.plural, resource_name
            )
