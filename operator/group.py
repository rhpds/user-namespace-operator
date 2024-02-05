import asyncio

from usernamespaceoperator import UserNamespaceOperator

class Group:
    instances = {}
    lock = asyncio.Lock()

    @staticmethod
    def get_groups_with_user(user_name):
        return [
            group for group in Group.instances.values() if group.has_user(user_name)
        ]

    @staticmethod
    async def preload():
        groups_list = await UserNamespaceOperator.custom_objects_api.list_cluster_custom_object(
            group = 'user.openshift.io',
            plural = 'groups',
            version = 'v1',
        )
        for definition in groups_list.get('items', []):
            await Group.register(definition=definition)

    @staticmethod
    async def register(definition):
        async with Group.lock:
            name = definition['metadata']['name']
            instance = Group.instances.get(name)
            if instance:
                instance.refresh(definition)
            else:
                instance = Group(definition)
                Group.instances[name] = instance
            return instance

    @staticmethod
    def unregister(name):
        return Group.instances.pop(name, None)

    def __init__(self, definition):
        self.prev_users = set()
        self.users = set(definition.get('users', []))
        self.definition = definition

    def __str__(self):
        return f"Group {self.name}"

    @property
    def name(self):
        return self.definition['metadata']['name']

    def has_user(self, user_name):
        return user_name in self.users

    def refresh(self, definition):
        self.prev_users = self.users
        self.users = set(definition.get('users', []))
        self.definition = definition
