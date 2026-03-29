from __future__ import annotations
from collections.abc import Mapping
from typing import Any

import kubernetes_asyncio

from usernamespaceoperator import UserNamespaceOperator

class K8sApiGroup:
    instances = {}

    @classmethod
    async def get(cls, api_group_version: str) -> K8sApiGroup:
        if api_group_version in cls.instances:
            return cls.instances.get(api_group_version)
        resp = await UserNamespaceOperator.custom_objects_api.api_client.call_api(
            method = 'GET',
            resource_path = f"/apis/{api_group_version}",
            auth_settings=['BearerToken'],
            response_types_map = {
                200: "object",
            }
        )
        return cls(resp[0])

    def __init__(self, resource_object: Mapping[str, Any]) -> None:
        self.name = resource_object['groupVersion'].split('/')[0]
        self.version = resource_object['apiVersion']
        self.resources = [
            K8sApiGroupResource(r) for r in resource_object.get('resources', [])
        ]

    def get_resource(self, kind) -> str|None:
        for resource in self.resources:
            if resource.kind == kind:
                return resource
        return None

class K8sApiGroupResource:
    def __init__(self, resource: Mapping[str, any]) -> None:
        self.kind = resource['kind']
        self.name = resource['name']
        self.namespaced = resource['namespaced']

    @property
    def plural(self) -> str:
        return self.name
