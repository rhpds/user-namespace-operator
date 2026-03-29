from __future__ import annotations
from collections.abc import Mapping
from typing import Any, List

import asyncio
import kubernetes_asyncio

from math import floor, log

from templating import check_condition, process_template
from usernamespaceoperator import UserNamespaceOperator

from group import Group
from user import User

class UserNamespaceRoleBinding:
    def __init__(self, spec: Mapping[str, Any]) -> None:
        self.spec = spec

    @property
    def role_name(self) -> str:
        return self.spec['roleName']

    @property
    def when(self) -> str|None:
        return self.spec.get('when')

    def check_condition(self, user: User, groups: List[Group]) -> bool:
        if self.when is None:
            return True

        group_names = [group.name for group in groups]

        return check_condition(
            self.when,
            {
                "groups": groups,
                "group_names": group_names,
                "user": user,
            }
        )

class UserNamespaceTemplate:
    def __init__(self, spec: Mapping[str, Any]) -> None:
        self.spec = spec

    @property
    def name(self) -> str:
        return self.spec['name']

    @property
    def namespace(self) -> str:
        return self.spec.get('namespace', UserNamespaceOperator.operator_namespace)

    @property
    def parameter_values(self) -> Mapping[str, Any]:
        return self.spec.get('parameterValues', {})

class UserNamespaceConfig:
    instances = {}
    lock = asyncio.Lock()

    @classmethod
    async def get(cls, name: str) -> UserNamespaceConfig:
        async with cls.lock:
            user_namespace_config = cls.instances.get(name)
            if user_namespace_config:
                return user_namespace_config
            definition = await UserNamespaceOperator.custom_objects_api.get_cluster_custom_object(
                group = UserNamespaceOperator.operator_domain,
                name = name,
                plural = 'usernamespaceconfigs',
                version = UserNamespaceOperator.operator_version,
            )
            return cls.__register_definition(definition=definition)

    @classmethod
    def list(cls) -> List[UserNamespaceConfig]:
        return list(cls.instances.values())

    @classmethod
    async def preload(cls) -> None:
        user_namespace_config_list = await UserNamespaceOperator.custom_objects_api.list_cluster_custom_object(
            group = UserNamespaceOperator.operator_domain,
            plural = 'usernamespaceconfigs',
            version = UserNamespaceOperator.operator_version,
        )
        for definition in user_namespace_config_list.get('items', []):
            await cls.register_definition(definition)

    @classmethod
    async def register(cls,
        name: str,
        spec: Mapping[str, Any],
        status: Mapping[str, Any],
        uid: str,
    ) -> UserNamespaceConfig:
        async with cls.lock:
            return cls.__register(name=name, spec=spec, status=status, uid=uid)

    @classmethod
    def __register(cls,
        name: str,
        spec: Mapping[str, Any],
        status: Mapping[str, Any],
        uid: str,
    ) -> UserNamespaceConfig:
        instance = cls.instances.get(name)
        if instance:
            instance.refresh(name=name, spec=spec, status=status, uid=uid)
        else:
            instance = cls(name=name, spec=spec, status=status, uid=uid)
            cls.instances[name] = instance
        return instance

    @classmethod
    async def register_definition(cls, definition: Mapping[str, Any]) -> UserNamespaceConfig:
        async with cls.lock:
            return cls.__register_definition(definition=definition)

    @classmethod
    def __register_definition(cls, definition: Mapping[str, Any]) -> UserNamespaceConfig:
        return cls.__register(
            name = definition['metadata']['name'],
            spec = definition['spec'],
            status = definition.get('status'),
            uid = definition['metadata']['uid'],
        )

    @classmethod
    async def unregister_config(cls, name:str) -> UserNamespaceConfig|None:
        async with cls.lock:
            return cls.instances.pop(name, None)

    def __init__(self,
        name: str,
        spec: Mapping[str, Any],
        status: Mapping[str, Any],
        uid: str,
        **_,
    ) -> None:
        self.name = name
        self.spec = spec
        self.status = status or {}
        self.uid = uid

    def __str__(self) -> str:
        return f"UserNamespaceConfig {self.name}"

    @property
    def autocreate_description(self) -> str|None:
        return self.spec.get('autocreate', {}).get('description')

    @property
    def autocreate_display_name(self) -> str|None:
        return self.spec.get('autocreate', {}).get('displayName')

    @property
    def autocreate_enable(self) -> bool:
        return self.spec.get('autocreate', {}).get('enable', False)

    @property
    def autocreate_prefix(self) -> str:
        return self.spec.get('autocreate', {}).get('prefix', 'user-')

    @property
    def autocreate_when(self) -> str|None:
        return self.spec.get('autocreate', {}).get('when')

    @property
    def description(self) -> str|None:
        return self.spec.get('description')

    @property
    def display_name(self) -> str|None:
        return self.spec.get('displayName')

    @property
    def reference(self) -> Mapping[str, str]:
        return dict(
            apiVersion = UserNamespaceOperator.operator_api_version,
            kind = 'UserNamespaceConfig',
            name = self.name,
            uid = self.uid
        )

    @property
    def management_interval_seconds(self) -> int:
        return self.spec.get('managementIntervalSeconds', 600)

    @property
    def role_bindings(self) -> List[UserNamespaceRoleBinding]:
        return [
            UserNamespaceRoleBinding(r) for r in self.spec.get('roleBindings', [])
        ]

    @property
    def templates(self) -> List[UserNamespaceRoleTemplate]:
        return [
            UserNamespaceTemplate(t) for t in self.spec.get('templates', [])
        ]

    async def autocreate_user_namespace(self,
        logger: loggers.ObjectLogger,
        user: User,
        groups: List[Group],
    ) -> None:
        """
        Create UserNamespace for user

        Ideally the UserNamespace will be named with a sanitized version of the
        user name, but there may be conflicts between the sanitized names and
        so the user namespace name may be given a numeric suffix.

        Kubernetes generate name is not used so that autocreated user namespaces
        will be obviously different from other UserNamespace resources.
        """
        from usernamespace import UserNamespace

        user_namespace_basename = self.autocreate_prefix + user.sanitized_name
        # Name truncated at k8s namespace length limit
        user_namespace_name = user_namespace_basename[:63]

        variables = {
            "groups": groups,
            "group_names": [group.name for group in groups],
            "user": user,
            "user_name": user.name,
        }

        description = self.autocreate_description
        if description is not None:
            description = process_template(description, variables)

        display_name = self.autocreate_display_name
        if display_name is not None:
            display_name = process_template(display_name, variables)

        i = 0
        while True:
            user_namespace = await UserNamespace.try_create(
                description = description,
                display_name = display_name,
                logger = logger,
                name = user_namespace_name,
                user = user,
                user_namespace_config = self,
            )
            if user_namespace:
                return
            i += 1
            # Name truncated at k8s namespace length limit with numeric extension
            user_namespace_name = f"{user_namespace_basename[:61 - floor(log(i, 10))]}-{i}"

    async def check_autocreate_user_namespace(self,
        logger: loggers.ObjectLogger,
        user: User,
    ) -> None:
        """
        Create UserNamespace object for user if autocreate is enabled and the
        user does not yet have a namespace created from this config.
        """
        async with user.lock:
            await self.check_autocreate_user_namespace_with_lock(logger=logger, user=user)

    async def check_autocreate_user_namespace_with_lock(self,
        logger: loggers.ObjectLogger,
        user: User,
    ) -> None:
        from usernamespace import UserNamespace

        if not self.autocreate_enable:
            return

        groups = Group.get_groups_with_user(user.name)

        if self.autocreate_when:
            if not check_condition(
                self.autocreate_when,
                {
                    "groups": groups,
                    "group_names": [group.name for group in groups],
                    "user": user,
                    "user_name": user.name,
                }
            ):
                return

        user_namespaces = UserNamespace.get_user_namespaces_for_config_and_user(
            user = user,
            user_namespace_config = self,
        )
        if not user_namespaces:
            await self.autocreate_user_namespace(logger=logger, user=user, groups=groups)

    async def check_autocreate_user_namespaces(self,
        logger: loggers.ObjectLogger,
    ):
        """
        Create UserNamespace for each user in the cluster if autocreate is enabled.
        """
        if not self.autocreate_enable:
            return
        _continue = None
        last_processed_user_name = None
        while True:
            try:
                user_list = await UserNamespaceOperator.custom_objects_api.list_cluster_custom_object(
                    group = 'user.openshift.io',
                    plural = 'users',
                    version = 'v1',
                    _continue = _continue,
                    limit = 50,
                )
                for user_definition in user_list.get('items', []):
                    user = await User.register(definition=user_definition)
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

    async def manage_user_namespaces(self,
        logger: loggers.ObjectLogger,
    ):
        from usernamespace import UserNamespace
        for user_namespace in UserNamespace.get_user_namespaces_for_config(self):
            await user_namespace.get_user_and_manage(logger=logger)

    def refresh(self,
        spec: Mapping[str, Any],
        status: Mapping[str, Any],
        uid: str,
        **_,
    ) -> None:
        self.spec = spec
        self.status = status or {}
        self.uid = uid

    def unregister(self) -> UserNamespaceConfig|None:
        return UserNamespaceConfig.instances.pop(self.name, None)
