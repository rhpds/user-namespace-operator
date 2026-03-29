from __future__ import annotations
from collections.abc import Mapping
from typing import Any, List

import asyncio

from usernamespaceoperator import UserNamespaceOperator

class Group:
    instances = {}
    lock = asyncio.Lock()

    @classmethod
    def get_groups_with_user(cls, user_name: str) -> List[Group]:
        return [
            group for group in cls.instances.values() if group.has_user(user_name)
        ]

    @classmethod
    async def preload(cls) -> None:
        groups_list = await UserNamespaceOperator.custom_objects_api.list_cluster_custom_object(
            group = 'user.openshift.io',
            plural = 'groups',
            version = 'v1',
        )
        for definition in groups_list.get('items', []):
            await cls.register(definition=definition)

    @classmethod
    async def register(cls, definition: Mapping[str, Any]) -> None:
        async with cls.lock:
            name = definition['metadata']['name']
            instance = cls.instances.get(name)
            if instance:
                instance.refresh(definition)
            else:
                instance = cls(definition)
                cls.instances[name] = instance
            return instance

    @classmethod
    def unregister(cls, name: str) -> Group|None:
        return cls.instances.pop(name, None)

    def __init__(self, definition: Mapping[str, Any]) -> None:
        self.prev_users = set()
        self.users = set(definition.get('users') or [])
        self.definition = definition

    def __str__(self) -> str:
        return f"Group {self.name}"

    @property
    def name(self) -> str:
        return self.definition['metadata']['name']

    def has_user(self, user_name: str) -> bool:
        return user_name in self.users

    def refresh(self, definition: Mapping[str, Any]) -> None:
        self.prev_users = self.users
        self.users = set(definition.get('users', []))
        self.definition = definition
