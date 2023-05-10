import asyncio
import kubernetes_asyncio
import re

from config import (
    custom_objects_api,
    operator_domain,
    operator_version,
)

import user_namespace as user_namespace_module
import user_namespace_config as user_namespace_config_module

class User:
    instances = {}
    lock = asyncio.Lock()

    @staticmethod
    async def get(name):
        async with User.lock:
            user = User.instances.get(name)
            if user:
                return user
            definition = await custom_objects_api.get_cluster_custom_object(
                group = 'user.openshift.io',
                name = name,
                plural = 'users',
                version = 'v1',
            )
            return User.__register(definition=definition)

    @staticmethod
    async def register(definition):
        async with User.lock:
            return User.__register(definition)

    @staticmethod
    def __register(definition):
        name = definition['metadata']['name']
        instance = User.instances.get(name)
        if instance:
            instance.refresh(definition)
        else:
            instance = User(definition)
            User.instances[name] = instance
        return instance

    def __init__(self, definition):
        self.definition = definition
        self.lock = asyncio.Lock()

    def __str__(self):
        return f"User {self.name}"

    @property
    def api_version(self):
        return self.definition['apiVersion']

    @property
    def kind(self):
        return self.definition['kind']

    @property
    def metadata(self):
        return self.definition['metadata']

    @property
    def name(self):
        return self.metadata['name']

    @property
    def reference(self):
        return dict(
            apiVersion = "user.openshift.io/v1",
            kind = "User",
            name = self.name,
            uid = self.uid,
        )

    @property
    def sanitized_name(self):
        return re.sub(r'[^a-z0-9]', '-', self.name.lower())

    @property
    def uid(self):
        return self.metadata['uid']

    def refresh(self, definition):
        self.definition = definition

    async def handle_delete(self, logger):
        async with self.lock:
            user_namespace_list = await custom_objects_api.list_cluster_custom_object(
                group = operator_domain,
                label_selector = f"{operator_domain}/user-uid={self.uid}",
                plural = 'usernamespaces',
                version = operator_version,
            )
            for user_namespace in user_namespace_list.get('items', []):
                user_namespace_name = user_namespace['metadata']['name']
                logger.info(f"Propagating deletion of {self} to UserNamespace {user_namespace_name}")
                try:
                    await custom_objects_api.delete_cluster_custom_object(
                        group = operator_domain,
                        name = user_namespace_name,
                        plural = 'usernamespaces',
                        version = operator_version,
                    )
                except kubernetes_asyncio.client.exceptions.ApiException as e:
                    if e.status != 404:
                        raise

    async def manage(self, logger):
        async with self.lock:
            for user_namespace in user_namespace_module.UserNamespace.get_user_namespaces_for_user(self):
                await user_namespace.manage(logger=logger, user=self)
            for user_namespace_config in user_namespace_config_module.UserNamespaceConfig.list():
                await user_namespace_config.check_autocreate_user_namespace_with_lock(logger=logger, user=self)

    async def manage_user_namespace(self, logger, user_namespace):
        async with self.lock:
            await user_namespace.manage(logger=logger, user=self)

    def unregister(self):
        User.instances.pop(self.name, None)
