import asyncio
import kubernetes_asyncio

from config import (
    core_v1_api,
    custom_objects_api,
    operator_api_version,
    operator_cluster_admin,
    operator_service_account_name,
    operator_domain,
    operator_namespace,
    operator_version,
    rbac_authorization_v1_api,
)

import user as user_module
import user_namespace_config as user_namespace_config_module

from k8s_api_group import K8sApiGroup

class UserNamespace:
    instances = {}
    lock = asyncio.Lock()

    @staticmethod
    async def create(name, user, user_namespace_config):
        definition = await custom_objects_api.create_cluster_custom_object(
            group = operator_domain,
            plural = 'usernamespaces',
            version = operator_version,
            body = {
                'apiVersion': operator_api_version,
                'kind': 'UserNamespace',
                'metadata': {
                    'name': name,
                    'labels': {
                        operator_domain + '/config': user_namespace_config.name,
                        operator_domain + '/user-uid': user.uid,
                    },
                    'ownerReferences': [dict(
                        controller = True,
                        **user.reference
                    )]
                },
                'spec': {
                    'config': user_namespace_config.reference,
                    'description': user_namespace_config.autocreate_description.format(user_name = user.name),
                    'displayName': user_namespace_config.autocreate_display_name.format(user_name = user.name),
                    'user': user.reference,
                }
            }
        )
        return await UserNamespace.register_definition(definition=definition)

    @staticmethod
    async def get(name):
        async with UserNamespace.lock:
            if name in UserNamespace.instances:
                return UserNamespace.instances[name]
            try:
                definition = await custom_objects_api.get_cluster_custom_object(
                    operator_domain, operator_version, 'usernamespaces', name
                )
                return UserNamespace.register_definition(definition)
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status == 404:
                    return None
                else:
                    raise

    @staticmethod
    def get_user_namespaces_for_config(user_namespace_config):
        return [
            user_namespace for user_namespace in UserNamespace.instances.values()
            if user_namespace.config_name == user_namespace_config.name
        ]

    @staticmethod
    def get_user_namespaces_for_user(user):
        return [
            user_namespace for user_namespace in UserNamespace.instances.values()
            if user_namespace.user_uid == user.uid
        ]

    @staticmethod
    def get_user_namespaces_for_config_and_user(user, user_namespace_config):
        return [
            user_namespace for user_namespace in UserNamespace.instances.values()
            if user_namespace.config_name == user_namespace_config.name and user_namespace.user_uid == user.uid
        ]

    @staticmethod
    async def preload():
        _continue = None
        while True:
            user_namespace_list = await custom_objects_api.list_cluster_custom_object(
                group = operator_domain,
                plural = 'usernamespaces',
                version = operator_version,
                _continue = _continue,
                limit = 50,
            )
            for definition in user_namespace_list.get('items', []):
                await UserNamespace.register_definition(definition)
            _continue = user_namespace_list['metadata'].get('continue')
            if not _continue:
                break

    @staticmethod
    async def register(name, spec, status, uid):
        async with UserNamespace.lock:
            instance = UserNamespace.instances.get(name)
            if instance:
                instance.refresh(spec=spec, status=status, uid=uid)
            else:
                instance = UserNamespace(name=name, spec=spec, status=status, uid=uid)
                UserNamespace.instances[name] = instance
            return instance

    @staticmethod
    async def register_definition(definition):
        return await UserNamespace.register(
            name = definition['metadata']['name'],
            spec = definition['spec'],
            status = definition.get('status'),
            uid = definition['metadata']['uid'],
        )

    @staticmethod
    def unregister(name):
        return UserNamespace.instances.pop(name, None)

    @staticmethod
    async def try_create(name, logger, user, user_namespace_config):
        # Get namespace, waiting for namespace deletion to complete if already initiated 
        try:
            while True:
                namespace = await core_v1_api.read_namespace(name)
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
        if namespace and not operator_cluster_admin:
            try:
                admin_role_binding = await rbac_authorization_v1_api.read_namespaced_role_binding(
                    name = 'admin',
                    namespace = namespace.metadata.name
                )
                if len(admin_role_binding.subjects) < 1:
                    return
                # Check the subject for the admin rolebinding
                if admin_role_binding.subjects[0].kind == 'ServiceAccount':
                    if admin_role_binding.subjects[0].name != operator_service_account_name \
                    or admin_role_binding.subjects[0].namespace != operator_namespace:
                        return
                # Odd bug? When a service account creates a project request the namespace creates an
                # admin rolebinding with kind "User"
                if admin_role_binding.subjects[0].kind == 'User':
                    if admin_role_binding.subjects[0].name != f"system:serviceaccount:{operator_namespace}:{operator_service_account_name}":
                        return
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status == 404 or e.status == 403:
                    return
                else:
                    raise

        # Try to create the UserNamespace object, accepting 409 conflict as a
        # normal failure to create.
        try:
            user_namespace = await UserNamespace.create(
                name = name,
                user = user,
                user_namespace_config = user_namespace_config,
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

    def __init__(self, name, spec, status, uid, **_):
        self.name = name
        self.spec = spec
        self.status = status or {}
        self.uid = uid

    def __str__(self):
        return f"UserNamespace {self.name}"

    @property
    def config_name(self):
        return self.spec.get('config', {}).get('name', 'default')

    @property
    def description(self):
        return self.spec.get('description', f'User namespace for {self.user_name}.')

    @property
    def display_name(self):
        return self.spec.get('displayName', f'User {self.user_name}')

    @property
    def managed_resources(self):
        return self.status.get('managedResources', [])

    @property
    def reference(self):
        return dict(
            apiVersion = operator_api_version,
            kind = 'UserNamespace',
            name = self.name,
            uid = self.uid,
        )

    @property
    def user_name(self):
        return self.user_reference['name']

    @property
    def user_reference(self):
        return self.spec['user']

    @property
    def user_uid(self):
        return self.user_reference['uid']

    def refresh(self, spec, status, uid):
        self.spec = spec
        self.status = status or {}
        self.uid = uid

    def refresh_from_definition(self, definition):
        self.spec = definition['spec']
        self.status = definition.get('status', {})
        self.uid = definition['metadata']['uid']

    async def check_update_namespace(self, logger, namespace, user):
        namespace_name = namespace.metadata.name
        updated = False

        if not namespace.metadata.annotations:
            logger.info('setting namespace annotations')
            namespace.metadata.annotations = {
                'openshift.io/description': self.description,
                'openshift.io/displayName': self.display_name,
                'openshift.io/requester': self.user_name,
            }
            updated = True
        else:
            if self.description != namespace.metadata.annotations.get('openshift.io/description', ''):
                logger.info('setting namespace description annotation')
                namespace.metadata.annotations['openshift.io/description'] = self.description
                updated = True
            if self.display_name != namespace.metadata.annotations.get('openshift.io/display-name', ''):
                logger.info('setting namespace display-name annotation')
                namespace.metadata.annotations['openshift.io/display-name'] = self.display_name
                updated = True
            if user.name != namespace.metadata.annotations.get('openshift.io/requester', ''):
                logger.info('setting namespace requester annotation')
                namespace.metadata.annotations['openshift.io/requester'] = user.name
                updated = True

        if not namespace.metadata.labels:
            logger.info('setting namespace user-uid label')
            namespace.metadata.labels = {
                operator_domain + '/user-uid': user.uid
            }
            updated = True
        elif user.uid != namespace.metadata.labels.get(operator_domain + '/user-uid', ''):
            logger.info('setting namespace user-uid label')
            namespace.metadata.labels[operator_domain + '/user-uid'] = user.uid
            updated = True

        if not namespace.metadata.owner_references:
            logger.info('setting namespace owner metadata')
            namespace.metadata.owner_references = [dict(
                controller = True,
                **self.reference
            )]
            updated = True

        if updated:
            await core_v1_api.replace_namespace(namespace_name, namespace)

    async def create_namespace(self, logger, user):
        if operator_cluster_admin:
            await core_v1_api.create_namespace(
                kubernetes_asyncio.client.V1Namespace(
                    metadata = kubernetes_asyncio.client.V1ObjectMeta(
                        annotations = {
                            'openshift.io/description': self.description,
                            'openshift.io/display-name': self.display_name,
                            'openshift.io/requester': user.name,
                        },
                        labels = {
                            f"{operator_domain}/user-uid": user.uid
                        },
                        owner_references = [
                            kubernetes_asyncio.client.V1OwnerReference(
                                api_version = operator_api_version,
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
            await rbac_authorization_v1_api.create_namespaced_role_binding(
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
                        kubernetes_asyncio.client.V1Subject(
                            kind = 'ServiceAccount',
                            name = operator_service_account_name,
                            namespace = operator_namespace,
                        )
                    ],
                )
            )

        else:
            # Create using a project request so that the operator will be made an
            # administrator.
            project_request = await custom_objects_api.create_cluster_custom_object(
                group = 'project.openshift.io',
                plural = 'projectrequests',
                version = 'v1',
                body = {
                    'apiVersion': 'project.openshift.io/v1',
                    'kind': 'ProjectRequest',
                    'metadata': {
                        'name': self.name,
                    },
                    'description': self.description,
                    'displayName': self.display_name,
                }
            )

            while True:
                try:
                    namespace = await core_v1_api.read_namespace(self.name)
                    logger.info(f"Namespace {self.name} created")
                    namespace.metadata.annotations['openshift.io/requester'] = user.name
                    namespace.metadata.labels = {
                        operator_domain + '/user-uid': user.uid
                    }
                    namespace.metadata.owner_references = [
                        kubernetes_asyncio.client.V1OwnerReference(
                            api_version = operator_api_version,
                            controller = True,
                            kind = 'UserNamespace',
                            name = self.name,
                            uid = self.uid,
                        )
                    ]
                    await core_v1_api.replace_namespace(namespace.metadata.name, namespace)
                    break
                except kubernetes_asyncio.client.exceptions.ApiException as e:
                    if e.status != 404 and e.status != 409:
                        raise

    async def delete(self, logger):
        try:
            await custom_objects_api.delete_cluster_custom_object(
                group = operator_domain,
                name = self.name,
                plural = 'usernamespaces',
                version = operator_version,
            )
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status != 404:
                raise

    async def get_config(self):
        if self.config_name:
            return await user_namespace_config_module.UserNamespaceConfig.get(self.config_name)
        else:
            return None

    async def get_user_and_manage(self, logger):
        try:
            user = await user_module.User.get(self.user_name)
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status == 404:
                logger.info("Deleteing {user_namespace} after user {user_namespace.user_name} not found")
                await self.delete(logger=logger)
                return
            else:
                raise
        await user.manage_user_namespace(logger=logger, user_namespace=self)

    async def manage(self, logger, user=None):
        await self.manage_namespace(logger=logger, user=user)
        await self.manage_resources(logger=logger, user=user)

    async def manage_core_resource(self, definition):
        kind = definition['kind']
        resource_name = definition['metadata']['name']
        namespace = definition['metadata'].get('namespace', None)
        create_namespaced = 'create_namespaced_' + inflection.underscore(kind)
        create_cluster = 'create_' + inflection.underscore(kind)
        relpace_namespaced = 'replace_namespaced_' + inflection.underscore(kind)
        replace_cluster = 'replace_' + inflection.underscore(kind)
        try:
            if hasattr(core_v1_api, create_namespaced):
                method = getattr(core_v1_api, create_namespaced)
                return await method(self.name, definition)
            else:
                method = getattr(core_v1_api, create_cluster)
                return await method(definition)
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        if hasattr(core_v1_api, replace_namespaced):
            method = getattr(core_v1_api, replace_namespaced)
            return await method(self.name, resource_name, definition)
        else:
            method = getattr(core_v1_api, replace_cluster)
            return await method(resource_name, definition)

    async def manage_custom_resource(self, definition):
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
                return await custom_objects_api.create_namespaced_custom_object(
                    api_group.name, api_group.version, self.name, api_resource.plural, definition
                )
            else:
                return await custom_objects_api.create_cluster_custom_object(
                    api_group.name, api_group.version, api_resource.plural, definition
                )
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status != 409:
                raise

        if api_resource.namespaced:
            return await custom_objects_api.replace_namespaced_custom_object(
                api_group.name, api_group.version, self.name, api_resource.plural, resource_name, definition
            )
        else:
            return await custom_objects_api.replace_cluster_custom_object(
                api_group.name, api_group.version, api_resource.plural, resource_name, definition
            )

    async def manage_namespace(self, logger, user):
        try:
            namespace = await core_v1_api.read_namespace(self.name)
            await self.check_update_namespace(logger=logger, namespace=namespace, user=user)
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status == 404:
                await self.create_namespace(logger=logger, user=user)
            else:
                raise

    async def manage_resource(self, definition):
        if '/' in definition['apiVersion']:
            return await self.manage_custom_resource(definition)
        else:
            return await self.manage_core_resource(definition)

    async def manage_resources(self, logger, user):
        groups = None
        resource_references = []
        if self.config_name:
            config = await self.get_config()
            if self.config_name and not config:
                raise kopf.TemporaryError(
                    f"Unable to find UserNamespaceConfig {self.config_name}",
                    delay = 600,
                )

            for template in config.templates:
                resource_references.extend(
                    await self.manage_template_resources(logger=logger, template=template)
                )

            for role_binding in config.role_bindings:
                if role_binding.check_condition(user=user):
                    resource_references.append(
                        await self.manage_role_binding(logger=logger, role_binding=role_binding, user=user)
                    )

        for reference in self.managed_resources:
            if reference not in resource_references:
                await self.remove_resource(logger=logger, resource_reference=reference)

        definition = await custom_objects_api.patch_cluster_custom_object_status(
            group = operator_domain,
            name = self.name,
            plural = 'usernamespaces',
            version = operator_version,
            _content_type = 'application/merge-patch+json',
            body = {
                "status": {
                    "managedResources": resource_references,
                }
            }
        )
        self.refresh_from_definition(definition=definition)

    async def manage_role_binding(self, logger, role_binding, user):
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

    async def manage_resource(self, definition):
        if '/' in definition['apiVersion']:
            return await self.manage_custom_resource(definition)
        else:
            return await self.manage_core_resource(definition)


    async def manage_template_resources(self, logger, template):
        template_resource = await custom_objects_api.get_namespaced_custom_object(
            'template.openshift.io', 'v1', template.namespace, 'templates', template.name
        )

        for parameter in template_resource.get('parameters', []):
            if parameter['name'] == 'PROJECT_NAME':
                parameter['value'] = self.name
            elif parameter['name'] == 'PROJECT_ADMIN_USER':
                parameter['value'] = self.user_name

        processed_template = await custom_objects_api.create_namespaced_custom_object(
            'template.openshift.io', 'v1', template.namespace, 'processedtemplates', template_resource
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

    async def remove_resource(self, logger, resource_reference):
        try:
            if '/' in resource_reference['apiVersion']:
                return await self.remove_custom_resource(logger=logger, resource_reference=resource_reference)
            else:
                return await self.remove_core_resource(logger=logger, resource_reference=resource_reference)
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            if e.status == 404:
                return None
            else:
                raise

    async def remove_core_resource(self, logger, resource_reference):
        kind = resource_reference['kind']
        resource_name = resource_reference['name']
        resource_namespace = resource_reference.get('namespace', None)
        if resource_namespace:
            logger.info(f"Removing {kind} {resource_name} from {resource_namespace}")
            method = getattr(core_v1_api, f"delete_namespaced_{inflection.underscore(kind)}")
            return await method(resource_name, resource_namespace)
        else:
            logger.info(f"Removing {kind} {resource_name}")
            method = getattr(core_v1_api, f"delete_{inflection.underscore(kind)}")
            return await method(resource_name)

    async def remove_custom_resource(self, logger, resource_reference):
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
            logger.info(f"Removing {api_group_version} {kind} {resource_name} from {resource_namespace}")
            return await custom_objects_api.delete_namespaced_custom_object(
                api_group.name, api_group.version, resource_namespace or self.name, api_resource.plural, resource_name
            )
        else:
            logger.info(f"Removing {api_group_version} {kind} {resource_name}")
            return await custom_objects_api.delete_cluster_custom_object(
                api_group.name, api_group.version, api_resource.plural, resource_name
            )
