import asyncio
import kubernetes_asyncio

from math import floor, log

from check_condition import check_condition
from config import custom_objects_api, operator_api_version, operator_domain, operator_namespace, operator_version

import group as group_module
import user as user_module
import user_namespace as user_namespace_module

class UserNamespaceRoleBinding:
    def __init__(self, spec):
        self.spec = spec

    @property
    def role_name(self):
        return self.spec['roleName']

    @property
    def when(self):
        return self.spec.get('when')

    def check_condition(self, user):
        if not self.when:
            return True

        groups = group_module.Group.get_groups_with_user(user.name)
        group_names = [group.name for group in groups]

        return check_condition(
            self.when,
            dict(
                groups = groups,
                group_names = group_names,
                user = user,
            )
        )

class UserNamespaceTemplate:
    def __init__(self, spec):
        self.spec = spec

    @property
    def name(self):
        return self.spec['name']

    @property
    def namespace(self):
        return self.spec.get('namespace', operator_namespace)

    @property
    def parameters(self):
        return self.spec.get('parameters', [])

class UserNamespaceConfig:
    instances = {}
    lock = asyncio.Lock()

    @staticmethod
    async def get(name):
        async with UserNamespaceConfig.lock:
            user_namespace_config = UserNamespaceConfig.instances.get(name)
            if user_namespace_config:
                return user_namespace_config
            definition = await custom_objects_api.get_cluster_custom_object(
                group = operator_domain,
                name = name,
                plural = 'usernamespaceconfigs',
                version = operator_version,
            )
            return UserNamespaceConfig.__register(definition=definition)

    @staticmethod
    def list():
        return list(UserNamespaceConfig.instances.values())

    @staticmethod
    async def preload():
        user_namespace_config_list = await custom_objects_api.list_cluster_custom_object(
            group = operator_domain,
            plural = 'usernamespaceconfigs',
            version = operator_version,
        )
        for definition in user_namespace_config_list.get('items', []):
            await UserNamespaceConfig.register_definition(definition)

    @staticmethod
    async def register(name, spec, status, uid):
        async with UserNamespaceConfig.lock:
            return UserNamespaceConfig.__register(name=name, spec=spec, status=status, uid=uid)

    @staticmethod
    def __register(name, spec, status, uid):
        instance = UserNamespaceConfig.instances.get(name)
        if instance:
            instance.refresh(name=name, spec=spec, status=status, uid=uid)
        else:
            instance = UserNamespaceConfig(name=name, spec=spec, status=status, uid=uid)
            UserNamespaceConfig.instances[name] = instance
        return instance

    @staticmethod
    def __register_definition(definition):
        return UserNamespaceConfig.__register(
            name = definition['metadata']['name'],
            spec = definition['spec'],
            status = definition.get('status'),
            uid = definition['metadata']['uid'],
        )

    @staticmethod
    async def register_definition(definition):
        async with UserNamespaceConfig.lock:
            UserNamespaceConfig.__register_definition(definition=definition)

    @staticmethod
    async def unregister_config(name):
        async with UserNamespaceConfig.lock:
            return UserNamespaceConfig.instances.pop(name, None)

    def __init__(self, name, spec, status, uid, **_):
        self.name = name
        self.spec = spec
        self.status = status or {}
        self.uid = uid

    def __str__(self):
        return f"UserNamespaceConfig {self.name}"

    @property
    def autocreate_description(self):
        return self.spec.get('autocreate', {}).get('description', 'User namespace for {user_name}.')

    @property
    def autocreate_display_name(self):
        return self.spec.get('autocreate', {}).get('displayName', 'User {user_name}')

    @property
    def autocreate_enable(self):
        return self.spec.get('autocreate', {}).get('enable', False)

    @property
    def autocreate_prefix(self):
        return self.spec.get('autocreate', {}).get('prefix', 'user-')

    @property
    def autocreate_when(self):
        return self.spec.get('autocreate', {}).get('when')

    @property
    def reference(self):
        return dict(
            apiVersion = operator_api_version,
            kind = 'UserNamespaceConfig',
            name = self.name,
            uid = self.uid
        )

    @property
    def management_interval_seconds(self):
        return self.spec.get('managementIntervalSeconds', 600)

    @property
    def role_bindings(self):
        return [
            UserNamespaceRoleBinding(r) for r in self.spec.get('roleBindings', [])
        ]

    @property
    def templates(self):
        return [
            UserNamespaceTemplate(t) for t in self.spec.get('templates', [])
        ]

    async def autocreate_user_namespace(self, logger, user):
        """
        Create UserNamespace for user

        Ideally the UserNamespace will be named with a sanitized version of the
        user name, but there may be conflicts between the sanitized names and
        so the user namespace name may be given a numeric suffix.

        Kubernetes generate name is not used so that autocreated user namespaces
        will be obviously different from other UserNamespace resources.
        """
        user_namespace_basename = self.autocreate_prefix + user.sanitized_name
        # Name truncated at k8s namespace length limit
        user_namespace_name = user_namespace_basename[:63]
        i = 0
        while True:
            user_namespace = await user_namespace_module.UserNamespace.try_create(
                logger = logger,
                name = user_namespace_name,
                user = user,
                user_namespace_config = self,
            )
            if user_namespace:
                return user_namespace
            i += 1
            # Name truncated at k8s namespace length limit with numeric extension
            user_namespace_name = f"{user_namespace_basename[:61 - floor(log(i, 10))]}-{i}"

    async def check_autocreate_user_namespace(self, logger, user):
        """
        Create UserNamespace object for user if autocreate is enabled and the
        user does not yet have a namespace created from this config.
        """
        async with user.lock:
            await self.check_autocreate_user_namespace_with_lock(logger=logger, user=user)

    async def check_autocreate_user_namespace_with_lock(self, logger, user):
        if not self.autocreate_enable:
            return False
        if self.autocreate_when:
            groups = group_module.Group.get_groups_with_user(user.name)
            group_names = [group.name for group in groups]
            if not check_condition(
                self.autocreate_when,
                dict(
                    groups = groups,
                    group_names = group_names,
                    user = user,
                )
            ):
                return False

        user_namespaces = user_namespace_module.UserNamespace.get_user_namespaces_for_config_and_user(
            user = user,
            user_namespace_config = self,
        )
        if not user_namespaces:
            await self.autocreate_user_namespace(logger=logger, user=user)

    async def check_autocreate_user_namespaces(self, logger):
        """
        Create UserNamespace for each user in the cluster if autocreate is enabled.
        """
        if not self.autocreate_enable:
            return
        _continue = None
        last_processed_user_name = None
        while True:
            try:
                user_list = await custom_objects_api.list_cluster_custom_object(
                    group = 'user.openshift.io',
                    plural = 'users',
                    version = 'v1',
                    _continue = _continue,
                    limit = 50,
                )
                for user_definition in user_list.get('items', []):
                    user = await user_module.User.register(definition=user_definition)
                    if last_processed_user_name and last_processed_user_name >= user.name:
                        continue
                    else:
                        last_processed_user_name = user.name
                    await self.check_autocreate_user_namespace(logger=logger, user=user)
                _continue = user_list['metadata'].get('continue')
                if not _continue:
                    break
            except kubernetes_asyncio.client.exceptions.ApiException as e:
                if e.status == 410:
                    # Query expired before completion, reset.
                    logger.info("Restarting user list for namespace management")
                    _continue = None
                else:
                    raise

    async def manage_user_namespaces(self, logger):
        for user_namespace in user_namespace_module.UserNamespace.get_user_namespaces_for_config(self):
            await user_namespace.get_user_and_manage(logger=logger)

    def refresh(self, spec, status, uid, **_):
        self.spec = spec
        self.status = status or {}
        self.uid = uid

    def unregister(self):
        return UserNamespaceConfig.instances.pop(self.name, None)
