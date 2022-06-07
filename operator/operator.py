import collections
import copy
import kopf
import kubernetes
import logging
import os
import re

if os.path.exists('/run/secrets/kubernetes.io/serviceaccount/token'):
    kubernetes.config.load_incluster_config()
else:
    kubernetes.config.load_kube_config()

core_v1_api = kubernetes.client.CoreV1Api()
custom_objects_api = kubernetes.client.CustomObjectsApi()
authorization_v1_api = kubernetes.client.AuthorizationV1Api()
rbac_authorization_v1_api = kubernetes.client.RbacAuthorizationV1Api()

check_interval = int(os.environ.get('CHECK_INTERVAL', 900))
operator_domain = os.environ.get('OPERATOR_DOMAIN', 'usernamespace.gpte.redhat.com')
operator_api_version = os.environ.get('OPERATOR_VERSION', 'v1')
operator_api_group_version = f"{operator_domain}/{operator_api_version}"
operator_service_account_name = os.environ.get('OPERATOR_SERVICE_ACCOUNT', 'user-namespace-operator')

try:
    with open('/run/secrets/kubernetes.io/serviceaccount/namespace') as f:
        operator_namespace = f.read().strip()
except FileNotFoundError:
    # Local testing?
    operator_namespace = os.environ.get('OPERATOR_NAMESPACE', 'user-namespace-operator')


try:
    cluster_admin_access_review = authorization_v1_api.create_self_subject_access_review(
        kubernetes.client.V1SelfSubjectAccessReview(
            spec = kubernetes.client.V1SelfSubjectAccessReviewSpec(
                resource_attributes = kubernetes.client.V1ResourceAttributes(
                    group='*', resource='*', verb='*'
                )
            )
        )
    )
    operator_cluster_admin = cluster_admin_access_review.status.allowed
except kubernetes.client.rest.ApiException as e:
    operator_cluster_admin = False


class ApiGroup:
    instances = {}

    @staticmethod
    def get(api_group_version):
        if api_group_version in ApiGroup.instances:
            return ApiGroup.instances.get(api_group_version)

        resp = custom_objects_api.api_client.call_api(
            '/apis/' + api_group_version,
            'GET', auth_settings=['BearerToken'], response_type='object'
        )
        return ApiGroup(resp[0])

    def __init__(self, resource_object):
        self.name = resource_object['groupVersion'].split('/')[0]
        self.version = resource_object['apiVersion']
        self.resources = [
            ApiGroupResource(r) for r in resource_object.get('resources', [])
        ]

    def get_resource(self, kind):
        for resource in self.resources:
            if resource.kind == kind:
                return resource


class ApiGroupResource:
    def __init__(self, resource):
        self.kind = resource['kind']
        self.name = resource['name']
        self.namespaced = resource['namespaced']

    @property
    def plural(self):
        return self.name


class InfiniteRelativeBackoff:
    def __init__(self, initial_delay=0.1, n=2, maximum=60):
        self.initial_delay = initial_delay
        self.n = n
        self.maximum = maximum

    def __iter__(self):
        c = 0
        while True:
            delay = self.initial_delay * self.n ** c
            if delay > self.maximum:
                break
            yield delay
            c += 1

        while True:
            yield self.maximum


class User:
    def __init__(self, logger, resource_object):
        self.logger = logger
        self.resource_object = resource_object

    @property
    def api_version(self):
        return self.resource_object['apiVersion']

    @property
    def kind(self):
        return self.resource_object['kind']

    @property
    def metadata(self):
        return self.resource_object['metadata']

    @property
    def name(self):
        return self.metadata['name']

    @property
    def reference(self):
        return dict(
            apiVersion = self.api_version,
            kind = self.kind,
            name = self.name,
            uid = self.uid,
        )

    @property
    def sanitized_name(self):
        return re.sub(r'[^a-z0-9]', '-', self.name.lower())

    @property
    def uid(self):
        return self.metadata['uid']

    def handle_delete(self):
        for user_namespace in custom_objects_api.list_cluster_custom_object(
            operator_domain, operator_api_version, 'usernamespaces',
            label_selector=f"{operator_domain}/user-uid={self.uid}"
        ).get('items', []):
            name = user_namespace['metadata']['name']
            self.logger.info(
                "Propagating User deletion to UserNamespace",
                extra = dict(
                    UserNamespace = dict(
                        apiVersion = operator_api_version,
                        kind = 'UserNamespace',
                        name = name,
                    )
                )
            )
            custom_objects_api.delete_cluster_custom_object(
                operator_domain, operator_api_version, 'usernamespaces', name
            )


class UserNamespace:
    @staticmethod
    def create(name, user, user_namespace_config):
        resource_object = custom_objects_api.create_cluster_custom_object(
            operator_domain, operator_api_version, 'usernamespaces',
            {
                'apiVersion': operator_api_group_version,
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
        return UserNamespace.from_resource_object(resource_object)

    @staticmethod
    def from_resource_object(resource_object):
        return UserNamespace(
            name = resource_object['metadata']['name'],
            spec = resource_object['spec'],
            status = resource_object.get('status'),
            uid = resource_object['metadata']['uid'],
        )

    @staticmethod
    def get(name):
        try:
            resource_object = custom_objects_api.get_cluster_custom_object(
                operator_domain, operator_api_version, 'usernamespaces', name
            )
        except kubernetes.client.rest.ApiException as e:
            if e.status != 404:
                return
            else:
                raise
        return UserNamespace.from_resource_object(resource_object)

    @staticmethod
    def try_create(name, user, user_namespace_config):
        # Check if namespace with this name already exists that is not for this
        # user by checking the requester annotation.
        namespace = None
        try:
            namespace = core_v1_api.read_namespace(name)
            if not namespace.metadata.annotations \
            or user.name != namespace.metadata.annotations.get('openshift.io/requester'):
                return
        except kubernetes.client.rest.ApiException as e:
            if e.status != 404:
                raise

        # Check user-namespace-operator has admin access to existing namespace
        if namespace and not operator_cluster_admin:
            try:
                admin_role_binding = rbac_authorization_v1_api.read_namespaced_role_binding('admin', namespace.metadata.name)
                if len(admin_role_binding.subjects) < 1:
                    return
                # Check the subject for the admin rolebinding
                if admin_role_binding.subjects[0].kind == 'ServiceAccount':
                    if admin_role_binding.subjects[0].name != operator_service_account_name \
                    or admin_role_binding.subjects[0].namespace != operator_namespace:
                        return
                # Odd bug? When a service account creates a project request the namespace creates an admin rolebinding with kind "User"
                if admin_role_binding.subjects[0].kind == 'User':
                    if admin_role_binding.subjects[0].name != f"system:serviceaccount:{operator_namespace}:{operator_service_account_name}":
                        return
            except kubernetes.client.rest.ApiException as e:
                if e.status == 404 or e.status == 403:
                    return
                else:
                    raise

        # Try to create the UserNamespace object, accepting 409 conflict as a
        # normal failure to create.
        try:
            user_namespace = UserNamespace.create(name=name, user=user, user_namespace_config=user_namespace_config)
            if namespace:
                user.logger.info(
                    "Autocreated UserNamespace for User to manage existing namespace",
                    extra = dict(
                        UserNamespace = user_namespace.reference,
                        UserNamespaceConfig = user_namespace_config.reference,
                    )
                )
            else:
                user.logger.info(
                    "Autocreated UserNamespace for User",
                    extra = dict(
                        UserNamespace = user_namespace.reference,
                        UserNamespaceConfig = user_namespace_config.reference,
                    )
                )
            return user_namespace

        except kubernetes.client.rest.ApiException as e:
            if e.status != 409:
                raise

    def __init__(
        self,
        name,
        spec,
        status,
        uid,
        logger = None,
        **_
    ):
        self.logger = logger
        self.name = name
        self.spec = spec
        self.status = status or {}
        self.uid = uid

    @property
    def config_name(self):
        return self.spec.get('config', {}).get('name')

    @property
    def description(self):
        return self.spec.get('description', f'User namespace for {self.user_name}.')

    @property
    def display_name(self):
        return self.spec.get('displayName', f'User {self.user_name}')

    @property
    def reference(self):
        return dict(
            apiVersion = operator_api_group_version,
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

    def check_delete(self):
        '''
        Check if user has been deleted and propagate delete if so.
        '''
        try:
            custom_objects_api.get_cluster_custom_object(
                'user.openshift.io', 'v1', 'users', self.user_name
            )
        except kubernetes.client.rest.ApiException as e:
            if e.status == 404:
                self.logger.info(
                    "Propagating delete from User",
                    extra = dict(
                        user=self.user_reference
                    )
                )
                self.delete()
            else:
                raise

    def check_update_namespace(self, namespace):
        config = UserNamespaceConfig.get(self.config_name) if self.config_name else None
        namespace_name = namespace.metadata.name
        updated = False

        if not namespace.metadata.annotations:
            self.logger.info('setting namespace annotations')
            namespace.metadata.annotations = {
                'openshift.io/description': self.description,
                'openshift.io/displayName': self.display_name,
                'openshift.io/requester': self.user_name,
            }
            updated = True
        else:
            if self.description != namespace.metadata.annotations.get('openshift.io/description', ''):
                self.logger.info('setting namespace description annotation')
                namespace.metadata.annotations['openshift.io/description'] = self.description
                updated = True
            if self.display_name != namespace.metadata.annotations.get('openshift.io/display-name', ''):
                self.logger.info('setting namespace display-name annotation')
                namespace.metadata.annotations['openshift.io/display-name'] = self.display_name
                updated = True
            if self.user_name != namespace.metadata.annotations.get('openshift.io/requester', ''):
                self.logger.info('setting namespace requester annotation')
                namespace.metadata.annotations['openshift.io/requester'] = self.user_name
                updated = True

        if not namespace.metadata.labels:
            self.logger.info('setting namespace user-uid label')
            namespace.metadata.labels = {
                operator_domain + '/user-uid': self.user_uid
            }
            updated = True
        elif self.user_uid != namespace.metadata.labels.get(operator_domain + '/user-uid', ''):
            self.logger.info('setting namespace user-uid label')
            namespace.metadata.labels[operator_domain + '/user-uid'] = self.user_uid
            updated = True

        if not namespace.metadata.owner_references:
            self.logger.info('setting namespace owner metadata')
            namespace.metadata.owner_references = [dict(
                controller = True,
                **self.reference
            )]
            updated = True

        if updated:
            core_v1_api.replace_namespace(namespace_name, namespace)

        if config:
            for template in config.templates:
                self.manage_template_resources(template)

    def create_namespace(self):
        config = UserNamespaceConfig.get(self.config_name) if self.config_name else None
        if self.config_name and not config:
            raise kopf.TemporaryError(
                f"Unable to find UserNamespaceConfig",
                extra = dict(
                    apiVersion = operator_api_group_version,
                    kind = 'UserNamespaceConfig',
                    name = self.config_name,
                ),
                delay = 60
            )

        if operator_cluster_admin:
            core_v1_api.create_namespace(
                kubernetes.client.V1Namespace(
                    metadata = kubernetes.client.V1ObjectMeta(
                        annotations = {
                            'openshift.io/description': self.description,
                            'openshift.io/displayName': self.display_name,
                            'openshift.io/requester': self.user_name,
                        },
                        labels = {
                            f"{operator_domain}/user-uid": self.user_uid
                        },
                        owner_references = [
                            kubernetes.client.V1OwnerReference(
                                api_version = operator_api_group_version,
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
            #  continue if cluster-admin privileges are ever removed.
            rbac_authorization_v1_api.create_namespaced_role_binding(
                self.name,
                kubernetes.client.V1RoleBinding(
                    metadata = kubernetes.client.V1ObjectMeta(
                        name = 'admin',
                    ),
                    role_ref = kubernetes.client.V1RoleRef(
                        api_group = 'rbac.authorization.k8s.io',
                        kind = 'ClusterRole',
                        name = 'admin',

                    ),
                    subjects = [
                        kubernetes.client.V1Subject(
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
            project_request = custom_objects_api.create_cluster_custom_object(
                'project.openshift.io', 'v1', 'projectrequests',
                {
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
                    namespace = core_v1_api.read_namespace(self.name)

                    self.logger.info(
                        'Namespace created',
                        extra = dict(
                            Namespace = dict(
                                apiVersion = 'v1',
                                kind = 'Namespace',
                                name = namespace.metadata.name,
                                uid = namespace.metadata.uid,
                            )
                        )
                    )

                    namespace.metadata.annotations['openshift.io/requester'] = self.user_name
                    namespace.metadata.labels = {
                        operator_domain + '/user-uid': self.user_uid
                    }
                    namespace.metadata.owner_references = [
                        kubernetes.client.V1OwnerReference(
                            api_version = operator_api_group_version,
                            controller = True,
                            kind = 'UserNamespace',
                            name = self.name,
                            uid = self.uid,
                        )
                    ]
                    core_v1_api.replace_namespace(namespace.metadata.name, namespace)
                    break
                except kubernetes.client.rest.ApiException as e:
                    if e.status != 404 and e.status != 409:
                        raise

        if config:
            for template in config.templates:
                self.manage_template_resources(template)

    def delete(self):
        try:
            custom_objects_api.delete_cluster_custom_object(
                operator_domain, operator_api_version, 'usernamespaces', self.name
            )
        except kubernetes.client.rest.ApiException as e:
            if e.status != 404:
                raise

    def manage_core_resource(self, resource_object):
        kind = resource_object['kind']
        resource_name = resource_object['metadata']['name']
        namespace = resource_object['metadata'].get('namespace', None)
        create_namespaced = 'create_namespaced_' + inflection.underscore(kind)
        create_cluster = 'create_' + inflection.underscore(kind)
        relpace_namespaced = 'replace_namespaced_' + inflection.underscore(kind)
        replace_cluster = 'replace_' + inflection.underscore(kind)
        try:
            if hasattr(core_v1_api, create_namespaced):
                method = getattr(core_v1_api, create_namespaced)
                return method(self.name, resource_object)
            else:
                method = getattr(core_v1_api, create_cluster)
                return method(resource_object)
        except kubernetes.client.rest.ApiException as e:
            if e.status != 409:
                raise

        if hasattr(core_v1_api, replace_namespaced):
            method = getattr(core_v1_api, replace_namespaced)
            return method(self.name, resource_name, resource_object)
        else:
            method = getattr(core_v1_api, replace_cluster)
            return method(resource_name, resource_object)

    def manage_custom_resource(self, resource_object):
        resource_name = resource_object['metadata']['name']
        api_group_version = resource_object['apiVersion']
        api_group = ApiGroup.get(api_group_version)
        if not api_group:
            raise kopf.TemporaryError(
                f"Unable to find information about apiVersion {api_group_version}",
                delay = 60
            )

        kind = resource_object['kind']
        api_resource = api_group.get_resource(kind = kind)
        if not api_resource:
            raise kopf.TemporaryError(
                f"Unable to find resource kind {kind} in apiVersion {api_group_version}",
                delay = 60
            )

        try:
            if api_resource.namespaced:
                return custom_objects_api.create_namespaced_custom_object(
                    api_group.name, api_group.version, self.name, api_resource.plural, resource_object
                )
            else:
                return custom_objects_api.create_cluster_custom_object(
                    api_group.name, api_group.version, api_resource.plural, resource_object
                )
        except kubernetes.client.rest.ApiException as e:
            if e.status != 409:
                raise

        if api_resource.namespaced:
            return custom_objects_api.replace_namespaced_custom_object(
                api_group.name, api_group.version, self.name, api_resource.plural, resource_name, resource_object
            )
        else:
            return custom_objects_api.replace_cluster_custom_object(
                api_group.name, api_group.version, api_resource.plural, resource_name, resource_object
            )

    def manage_namespace(self):
        try:
            namespace = core_v1_api.read_namespace(self.name)
            self.check_update_namespace(namespace)
        except kubernetes.client.rest.ApiException as e:
            if e.status == 404:
                self.create_namespace()
            else:
                raise

    def manage_resource(self, resource_object):
        if '/' in resource_object['apiVersion']:
            return self.manage_custom_resource(resource_object)
        else:
            return self.manage_core_resource(resource_object)

    def manage_template_resources(self, template):
        template_resource = custom_objects_api.get_namespaced_custom_object(
            'template.openshift.io', 'v1', template.namespace, 'templates', template.name
        )

        for parameter in template_resource.get('parameters', []):
            if parameter['name'] == 'PROJECT_NAME':
                parameter['value'] = self.name
            elif parameter['name'] == 'PROJECT_ADMIN_USER':
                parameter['value'] = self.user_name

        processed_template = custom_objects_api.create_namespaced_custom_object(
            'template.openshift.io', 'v1', template.namespace, 'processedtemplates', template_resource
        )

        for resource_object in processed_template.get('objects', []):
            self.manage_resource(resource_object)


class UserNamespaceConfig:
    instances = {}

    @staticmethod
    def get(name):
        return UserNamespaceConfig.instances.get(name)

    @staticmethod
    def preload():
        for resource_object in custom_objects_api.list_cluster_custom_object(
            operator_domain, operator_api_version, 'usernamespaceconfigs'
        ).get('items', []):
            UserNamespaceConfig.register(resource_object)

    @staticmethod
    def register(resource_object):
        name = resource_object['metadata']['name']
        instance = UserNamespaceConfig.instances.get(name)
        if instance:
            instance.__init__(resource_object)
        else:
            instance = UserNamespaceConfig(resource_object)
            UserNamespaceConfig.instances[name] = instance
        return instance

    @staticmethod
    def unregister(name):
        return UserNamespaceConfig.instances.pop(name, None)

    def __init__(self, resource_object):
        self.resource_object = resource_object

    @property
    def api_version(self):
        return self.resource_object['apiVersion']

    @property
    def autocreate_description(self):
        return self.resource_object['spec'].get('autocreate', {}).get('description', 'User namespace for {user_name}.')

    @property
    def autocreate_display_name(self):
        return self.resource_object['spec'].get('autocreate', {}).get('displayName', 'User {user_name}')

    @property
    def autocreate_enable(self):
        return self.resource_object['spec'].get('autocreate', {}).get('enable', False)

    @property
    def autocreate_prefix(self):
        return self.resource_object['spec'].get('autocreate', {}).get('prefix', 'user-')

    @property
    def kind(self):
        return self.resource_object['kind']

    @property
    def metadata(self):
        return self.resource_object['metadata']

    @property
    def name(self):
        return self.metadata['name']

    @property
    def reference(self):
        return dict(
            apiVersion = self.api_version,
            kind = self.kind,
            name = self.name,
            uid = self.uid
        )

    @property
    def spec(self):
        return self.resource_object['spec']

    @property
    def templates(self):
        return [
            UserNamespaceTemplate(t) for t in self.spec.get('templates', [])
        ]

    @property
    def uid(self):
        return self.metadata['uid']

    def autocreate_user_namespace(self, user):
        """
        Create UserNamespace for user

        Ideally the UserNamespace will be named with a sanitized version of the
        user name, but there may be conflicts between the sanitized names and
        so the user namespace name may be given a numeric suffix.

        Kubernetes generate name is not used so that autocreated user namespaces
        will be obviously different from other UserNamespace resources.
        """
        user_namespace_basename = self.autocreate_prefix + user.sanitized_name
        user_namespace_name = user_namespace_basename
        i = 0
        while True:
            user_namespace = UserNamespace.try_create(
                name = user_namespace_name,
                user = user,
                user_namespace_config = self,
            )
            if user_namespace:
                return user_namespace
            i += 1
            user_namespace_name = f"{user_namespace_basename}-{i}"

    def check_autocreate_user_namespace(self, user):
        """
        Create UserNamespace object for user if autocreate is enabled and the
        user does not yet have a namespace created from this config.
        """
        if not self.autocreate_enable:
            return False
        user_namespaces = self.get_user_namespaces_for_user(user)
        if not user_namespaces:
            self.autocreate_user_namespace(user)

    def get_user_namespaces_for_user(self, user):
        label_selector = f"{operator_domain}/user-uid={user.uid}"

        # Older versions did not apply config  label for default
        if self.name != 'default':
            label_selector += f",{operator_domain}/config={self.name}"

        user_namespaces = custom_objects_api.list_cluster_custom_object(
            operator_domain, operator_api_version, 'usernamespaces', label_selector=label_selector
        ).get('items', [])

        if self.name == 'default':
            return [
                uns for uns in user_namespaces
                if 'default' == uns['metadata']['labels'].get(f"{operator_domain}/config", 'default')
            ]
        else:
            return user_namespaces

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


@kopf.on.startup()
def startup(logger, settings: kopf.OperatorSettings, **_):
    # Never give up from network errors
    settings.networking.error_backoffs = InfiniteRelativeBackoff()

    # Use operator domain as finalizer
    settings.persistence.finalizer = operator_domain

    # Store progress in status.
    settings.persistence.progress_storage = kopf.StatusProgressStorage(field='status.kopf.progress')

    # Only create events for warnings and errors
    settings.posting.level = logging.WARNING

    # Disable scanning for CustomResourceDefinitions updates
    settings.scanning.disabled = True

    # Load all UserNamespaceConfig definitions
    UserNamespaceConfig.preload()

    if operator_cluster_admin:
        logger.info("Running as cluster-admin")
    else:
        logger.info("Running without cluster-admin privileges")


@kopf.on.event('user.openshift.io', 'v1', 'users')
def user_event(event, logger, **_):
    resource_object = event.get('object')

    if not resource_object \
    or resource_object['kind'] != 'User':
        return

    user = User(
        logger = logger,
        resource_object = resource_object,
    )

    if event['type'] == 'DELETED':
        user.handle_delete()
    else:
        for user_namespace_config in UserNamespaceConfig.instances.values():
            user_namespace_config.check_autocreate_user_namespace(user)


@kopf.on.create(operator_domain, operator_api_version, 'usernamespaces', id='usernamespace_create')
@kopf.on.resume(operator_domain, operator_api_version, 'usernamespaces', id='usernamespace_resume')
@kopf.on.update(operator_domain, operator_api_version, 'usernamespaces', id='usernamespace_update')
def usernamespace_handler(**kwargs):
    user_namespace = UserNamespace(**kwargs)
    user_namespace.manage_namespace()

@kopf.timer(operator_domain, operator_api_version, 'usernamespaces', interval=check_interval)
def usernamespace_check_delete(**kwargs):
    '''
    Periodically check if UserNamespace should be deleted following User deletion.
    OpenShift does not currently propagate deletes for users following owner references.
    '''
    user_namespace = UserNamespace(**kwargs)
    user_namespace.check_delete()


@kopf.on.event(operator_domain, operator_api_version, 'usernamespaceconfigs')
def usernamespaceconfig(event, **_):
    '''
    Watch UserNamespaceConfigs for updates.
    '''
    obj = event.get('object')
    if obj.get('kind') != 'UserNamespaceConfig':
        return
    if event['type'] == 'DELETED':
        UserNamespaceConfig.unregister(obj['metadata']['name'])
    else:
        UserNamespaceConfig.register(obj)
