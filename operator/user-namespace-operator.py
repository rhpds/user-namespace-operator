import collections
import copy
import kopf
import kubernetes
import os
import re

autocreate_user_namespaces = True \
   if re.match(r'^[ty]', os.environ.get('AUTOCREATE_USER_NAMESPACES', 't'), re.IGNORECASE) \
   else False

user_namespace_prefix = os.environ.get('USER_NAMESPACE_PREFIX', 'user-')

api_groups = {}

operator_domain = os.environ.get('OPERATOR_DOMAIN', 'usernamespace.gpte.redhat.com')

try:
    with open('/run/secrets/kubernetes.io/serviceaccount/namespace') as f:
        operator_namespace = f.read().strip()
except FileNotFoundError:
    # Local testing?
    operator_namespace = os.environ.get('OPERATOR_NAMESPACE', 'user-namespace-operator')

if os.path.exists('/run/secrets/kubernetes.io/serviceaccount/token'):
    f = open('/run/secrets/kubernetes.io/serviceaccount/token')
    kube_auth_token = f.read()
    kube_config = kubernetes.client.Configuration()
    kube_config.api_key['authorization'] = 'Bearer ' + kube_auth_token
    kube_config.host = os.environ['KUBERNETES_PORT'].replace('tcp://', 'https://', 1)
    kube_config.ssl_ca_cert = '/run/secrets/kubernetes.io/serviceaccount/ca.crt'
else:
    kubernetes.config.load_kube_config()
    kube_config = None

core_v1_api = kubernetes.client.CoreV1Api(
    kubernetes.client.ApiClient(kube_config)
)

custom_objects_api = kubernetes.client.CustomObjectsApi(
    kubernetes.client.ApiClient(kube_config)
)

def sanitize_user_name(user_name):
    return re.sub(r'[^a-z0-9]', '-', user_name.lower())

def autocreate_user_namespace(user, logger):
    """
    Create UserNamespace for user

    Ideally the UserNamespace will be named with a sanitized version of the
    user name, but there may be conflicts between the sanitized names and
    so the user namespace name may be given a numeric suffix.

    Kubernetes generate name is not used so that autocreated user namespaces
    will be obviously different from other UserNamespace resources.
    """
    user_name = user['metadata']['name']
    user_namespace_basename = user_namespace_prefix + sanitize_user_name(user_name)
    if not get_user_namespace(user_namespace_basename, logger):
        create_user_namespace(user_namespace_basename, user, logger)
    else:
        for i in range(1, 999):
            user_namespace_name = '{}-{}'.format(user_namespace_basename, 1)
            if not get_user_namespace(user_namespace_name, logger):
                create_user_namespace(user_namespace_name, user, logger)

def check_create_namespace(user_namespace, logger):
    name = user_namespace['metadata']['name']
    logger.debug('checking namespace %s', name)
    try:
        namespace = core_v1_api.read_namespace(name)
        logger.debug('namespace %s exists', name)
        check_namespace(namespace, user_namespace, logger)
    except kubernetes.client.rest.ApiException as e:
        if e.status == 404:
            create_namespace(user_namespace, logger)
        else:
            raise

def check_autocreate_user_namespace(user, logger):
    """Check if UserNamespace exists for user and create if not"""
    user_namespaces = get_user_namespaces_for_user(user, logger)
    if not user_namespaces:
        autocreate_user_namespace(user, logger)

def check_namespace(namespace, user_namespace, logger):
    namespace_name = namespace.metadata.name
    user_ref = user_namespace['spec']['user']
    user_name = user_ref['name']
    user_uid = user_ref['uid']
    updated = False

    if not namespace.metadata.annotations:
        logger.info('setting namespace requester annotation')
        namespace.metadata.annotations = {'openshift.io/requester', user_name}
        updated = True
    elif user_name != namespace.metadata.annotations.get('openshift.io/requester', ''):
        logger.info('setting namespace requester annotation')
        namespace.metadata.annotations['openshift.io/requester'] = user_name
        updated = True

    if not namespace.metadata.labels:
        logger.info('setting namespace user-uid label')
        namespace.metadata.labels =  {operator_domain + '/user-uid': user_ref['uid']}
        updated = True
    elif user_uid != namespace.metadata.labels.get(operator_domain + '/user-uid', ''):
        logger.info('setting namespace user-uid label')
        namespace.metadata.labels[operator_domain + '/user-uid'] = user_ref['uid']
        updated = True

    owner_reference = copy.copy(user_ref)
    owner_reference['controller'] = True
    if not namespace.metadata.owner_references:
        logger.info('setting namespace owner metadata')
        namespace.metadata.owner_references = [owner_reference]
        updated = True

    if updated:
        core_v1_api.replace_namespace(namespace_name, namespace)

def create_namespace(user_namespace, logger):
    user_namespace_meta = user_namespace['metadata']
    user_namespace_name = user_namespace_meta['name']
    user_ref = user_namespace['spec']['user']
    user_name = user_ref['name']
    logger.info('creating namespace')

    project_request = custom_objects_api.create_cluster_custom_object(
        'project.openshift.io', 'v1', 'projectrequests',
        {
            'apiVersion': 'project.openshift.io/v1',
            'kind': 'ProjectRequest',
            'metadata': {
                'name': user_namespace_name
            },
            'description': 'User Namespace for ' + user_name,
            'displayName': user_namespace_name
        }
    )

    namespace_updated = False
    for i in range(5):
        try:
            namespace = core_v1_api.read_namespace(user_namespace_name)
            namespace.metadata.annotations['openshift.io/requester'] = user_name
            namespace.metadata.labels = { operator_domain + '/user-uid': user_ref['uid'] }
            namespace.metadata.owner_references = [
                kubernetes.client.V1OwnerReference(
                    api_version = 'v1',
                    controller = True,
                    kind = 'UserNamespace',
                    name = user_namespace_name,
                    uid = user_namespace_meta['uid']
                )
            ]
            core_v1_api.replace_namespace(user_namespace_name, namespace)
            namespace_updated = True
            break
        except kubernetes.client.rest.ApiException as e:
            if e.status == 409:
                logger.warning("Conflict  %s", user_namespace_name)
            else:
                raise

    if namespace_updated:
        # FIXME - For now the namespace config is hard-coded to default
        init_namespace(user_namespace, 'default', logger)
    else:
        logger.error("Failed to update namespace")

def init_namespace(user_namespace, user_namespace_config_name, logger):
    try:
        user_namespace_config = custom_objects_api.get_cluster_custom_object(
            operator_domain, 'v1', 'usernamespaceconfigs', user_namespace_config_name
        )
    except kubernetes.client.rest.ApiException as e:
        if e.status == 404:
            logger.warning("Unable to access UserNamespaceConfig %s", user_namespace_config_name)
            return
        else:
            raise

    for template in user_namespace_config['spec']['templates']:
        logger.info("Applying template %s", template)
        apply_template_for_user_namespace(
            user_namespace, user_namespace_config_name,
            template['name'], template.get('namespace', operator_namespace),
            logger
        )

def apply_template_for_user_namespace(user_namespace, user_namespace_config, template_name, template_namespace, logger):
    user_namespace_meta = user_namespace['metadata']
    user_namespace_name = user_namespace_meta['name']
    user_ref = user_namespace['spec']['user']
    user_name = user_ref['name']

    try:
        template = custom_objects_api.get_namespaced_custom_object(
            'template.openshift.io', 'v1', operator_namespace, 'templates', template_name
        )
    except kubernetes.client.rest.ApiException as e:
        if e.status == 404:
            logger.warning("Unable to access template %s in %s to initialize namespace", template_name, template_namespace)
            return
        else:
            raise

    # FIXME - Is there a python library for processing templates?
    for template_object in template.get('objects', []):
        resource_definition = rec_string_sub(template_object, {
            '${PROJECT_NAME}': user_namespace_name,
            '${PROJECT_ADMIN_USER}': user_name
        })
        if 'namespace' not in resource_definition['metadata']:
            resource_definition['metadata']['namespace'] = user_namespace_name
        create_resource(resource_definition, logger)

def create_resource(resource_definition, logger):
    if '/' in resource_definition['apiVersion']:
        return create_custom_resource(resource_definition, logger)
    else:
        return create_core_resource(resource_definition, logger)

def create_core_resource(resource_definition, logger):
    kind = resource_definition['kind']
    namespace = resource_definition['metadata'].get('namespace', None)
    if namespace:
        method = getattr(
            core_v1_api, 'create_namespaced_' + inflection.underscore(kind)
        )
        return method(namespace, resource_definition)
    else:
        method = getattr(
            core_v1_api, 'create_' + inflection.underscore(kind)
        )
        return method(resource_definition)

def create_custom_resource(resource_definition, logger):
    group, version = resource_definition['apiVersion'].split('/')
    namespace = resource_definition['metadata'].get('namespace', None)
    plural = kind_to_plural(group, version, resource_definition['kind'])
    if namespace:
        return custom_objects_api.create_namespaced_custom_object(
            group, version, namespace, plural, resource_definition
        )
    else:
        return custom_objects_api.create_cluster_custom_object(
            group, version, plural, resource_definition
        )

def create_user_namespace(user_namespace_name, user, logger):
    user_meta = user['metadata']
    user_name = user_meta['name']

    logger.info('Creating UserNamespace %s for %s', user_namespace_name, user_name)
    custom_objects_api.create_cluster_custom_object(
        operator_domain, 'v1', 'usernamespaces',
        {
            'apiVersion': operator_domain + '/v1',
            'kind': 'UserNamespace',
            'metadata': {
                'name': user_namespace_name,
                'labels': {
                    operator_domain + '/user-uid': user_meta['uid']
                },
                'ownerReferences': [{
                    'apiVersion': user['apiVersion'],
                    'controller': True,
                    'kind': user['kind'],
                    'name': user_name,
                    'uid': user_meta['uid']
                }]
            },
            'spec': {
                'user': {
                    'apiVersion': user['apiVersion'],
                    'kind': user['kind'],
                    'name': user_name,
                    'uid': user['metadata']['uid']
                }
            }
        }
    )

def get_user_namespace(user_namespace_name, logger):
    try:
        return custom_objects_api.get_cluster_custom_object(
            operator_domain, 'v1', 'usernamespaces', user_namespace_name
        )
    except kubernetes.client.rest.ApiException as e:
        if e.status == 404:
            return None
        else:
            raise

def get_user_namespaces_for_user(user, logger):
    user_meta = user['metadata']
    return custom_objects_api.list_cluster_custom_object(
        operator_domain, 'v1', 'usernamespaces',
        label_selector='{}/user-uid={}'.format(operator_domain, user_meta['uid'])
    ).get('items', [])

def handle_user_namespace(user_namespace, logger):
    check_create_namespace(user_namespace, logger)

def kind_to_plural(group, version, kind):
    if group in api_groups \
    and version in api_groups[group]:
        for resource in api_groups[group][version]['resources']:
            if resource['kind'] == kind:
                return resource['name']

    resp = custom_objects_api.api_client.call_api(
        '/apis/{}/{}'.format(group,version),
        'GET', response_type='object'
    )
    group_info = resp[0]
    if group not in api_groups:
        api_groups[group] = {}
    api_groups[group][version] = group_info

    for resource in group_info['resources']:
        if resource['kind'] == kind:
            return resource['name']

    raise Exception('Unable to find kind {} in {}/{}', kind, group, version)

def rec_string_sub(target, substitutions):
    ret = copy.deepcopy(target)
    __rec_string_sub(ret, substitutions)
    return ret

def __rec_string_sub(target, substitutions):
    if isinstance(target, dict):
        for k, v in target.items():
            if isinstance(v, str):
                for a, b in substitutions.items():
                    v = v.replace(a, b)
                target[k] = v
            elif isinstance(v, (dict, list)):
                __rec_string_sub(v, substitutions)
    elif isinstance(target, list):
        for i, v in enumerate(target):
            if isinstance(v, str):
                for a, a in substitutions.items():
                    v = v.replace(a, b)
            elif isinstance(v, (dict, list)):
                __rec_string_sub(v, substitutions)
                target[i] = v

@kopf.on.event('user.openshift.io', 'v1', 'users')
def user_handler(event, logger, **_):
    user = event['object']
    if event['type'] in ['ADDED', 'MODIFIED', None]:
        if autocreate_user_namespaces:
            check_autocreate_user_namespace(user, logger)

@kopf.on.event(operator_domain, 'v1', 'usernamespaces')
def user_namespace_handler(event, logger, **_):
    user_namespace = event['object']
    user_namespace_meta = user_namespace['metadata']
    if event['type'] in ['ADDED', 'MODIFIED', None]:
        handle_user_namespace(user_namespace, logger)
