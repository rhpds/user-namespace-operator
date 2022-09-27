#!/usr/bin/env python

import kubernetes_asyncio

from config import custom_objects_api

class K8sApiGroup:
    instances = {}

    @staticmethod
    async def get(api_group_version):
        if api_group_version in K8sApiGroup.instances:
            return K8sApiGroup.instances.get(api_group_version)
        resp = await custom_objects_api.api_client.call_api(
            method = 'GET',
            resource_path = f"/apis/{api_group_version}",
            auth_settings=['BearerToken'],
            response_types_map = {
                200: "object",
            }
        )
        return K8sApiGroup(resp[0])

    def __init__(self, resource_object):
        self.name = resource_object['groupVersion'].split('/')[0]
        self.version = resource_object['apiVersion']
        self.resources = [
            K8sApiGroupResource(r) for r in resource_object.get('resources', [])
        ]

    def get_resource(self, kind):
        for resource in self.resources:
            if resource.kind == kind:
                return resource

class K8sApiGroupResource:
    def __init__(self, resource):
        self.kind = resource['kind']
        self.name = resource['name']
        self.namespaced = resource['namespaced']

    @property
    def plural(self):
        return self.name
