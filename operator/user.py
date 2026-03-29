from __future__ import annotations
from collections.abc import Mapping
from typing import Any, List

import asyncio
import re

import kubernetes_asyncio
from kopf._core.actions import loggers

from usernamespaceoperator import UserNamespaceOperator

class User:
    instances = {}
    lock = asyncio.Lock()

    @classmethod
    async def get(cls, name: str) -> User:
        async with cls.lock:
            user = cls.instances.get(name)
            if user:
                return user
            definition = await UserNamespaceOperator.custom_objects_api.get_cluster_custom_object(
                group = 'user.openshift.io',
                name = name,
                plural = 'users',
                version = 'v1',
            )
            return cls.__register(definition=definition)

    @classmethod
    async def register(cls, definition: Mapping[str, Any]) -> User:
        async with cls.lock:
            return cls.__register(definition)

    @classmethod
    def __register(cls, definition: Mpping[str, Any]) -> User:
        name = definition['metadata']['name']
        instance = cls.instances.get(name)
        if instance:
            instance.refresh(definition)
        else:
            instance = cls(definition)
            cls.instances[name] = instance
        return instance

    def __init__(self, definition: Mpping[str, Any]) -> None:
        self.definition = definition
        self.lock = asyncio.Lock()

    def __str__(self) -> str:
        return f"User {self.name}"

    @property
    def api_version(self) -> str:
        return self.definition['apiVersion']

    @property
    def kind(self) -> str:
        return self.definition['kind']

    @property
    def metadata(self) -> Mapping[str, Any]:
        return self.definition['metadata']

    @property
    def name(self) -> str:
        return self.metadata['name']

    @property
    def reference(self) -> Mapping[str, str]:
        return {
            "apiVersion": "user.openshift.io/v1",
            "kind": "User",
            "name": self.name,
            "uid": self.uid,
        }

    @property
    def sanitized_name(self) -> str:
        return re.sub(r'[^a-z0-9]', '-', self.name.lower())

    @property
    def uid(self) -> str:
        return self.metadata['uid']

    def refresh(self, definition) -> None:
        self.definition = definition

    async def handle_delete(self,
        logger: loggers.ObjectLogger,
    ) -> None:
        async with self.lock:
            user_namespace_list = await UserNamespaceOperator.custom_objects_api.list_cluster_custom_object(
                group = UserNamespaceOperator.operator_domain,
                label_selector = f"{UserNamespaceOperator.operator_domain}/user-uid={self.uid}",
                plural = 'usernamespaces',
                version = UserNamespaceOperator.operator_version,
            )
            for user_namespace in user_namespace_list.get('items', []):
                user_namespace_name = user_namespace['metadata']['name']
                logger.info(f"Propagating deletion of {self} to UserNamespace {user_namespace_name}")
                try:
                    await UserNamespaceOperator.custom_objects_api.delete_cluster_custom_object(
                        group = UserNamespaceOperator.operator_domain,
                        name = user_namespace_name,
                        plural = 'usernamespaces',
                        version = UserNamespaceOperator.operator_version,
                    )
                except kubernetes_asyncio.client.exceptions.ApiException as e:
                    if e.status != 404:
                        raise

    async def manage(self,
        logger: loggers.ObjectLogger,
    ) -> None:
        from usernamespaceconfig import UserNamespaceConfig
        from usernamespace import UserNamespace
        async with self.lock:
            for user_namespace in UserNamespace.get_user_namespaces_for_user(self):
                await user_namespace.manage(logger=logger, user=self)
            for user_namespace_config in UserNamespaceConfig.list():
                await user_namespace_config.check_autocreate_user_namespace_with_lock(logger=logger, user=self)

    def unregister(self) -> None:
        User.instances.pop(self.name, None)
