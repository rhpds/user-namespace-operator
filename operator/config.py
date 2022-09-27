import asyncio
import kubernetes_asyncio
import os

check_interval = int(os.environ.get('CHECK_INTERVAL', 900))
operator_domain = os.environ.get('OPERATOR_DOMAIN', 'usernamespace.gpte.redhat.com')
operator_version = os.environ.get('OPERATOR_VERSION', 'v1')
operator_api_version = f"{operator_domain}/{operator_version}"
operator_service_account_name = os.environ.get('OPERATOR_SERVICE_ACCOUNT', 'user-namespace-operator')
operator_cluster_admin = False

if os.path.exists('/run/secrets/kubernetes.io/serviceaccount'):
    kubernetes_asyncio.config.load_incluster_config()
    with open('/run/secrets/kubernetes.io/serviceaccount/namespace') as f:
        operator_namespace = f.read()
else:
    asyncio.get_event_loop().run_until_complete(kubernetes_asyncio.config.load_kube_config())
    operator_namespace = kubernetes_asyncio.config.list_kube_config_contexts()[1]['context']['namespace']

core_v1_api = kubernetes_asyncio.client.CoreV1Api()
custom_objects_api = kubernetes_asyncio.client.CustomObjectsApi()
authorization_v1_api = kubernetes_asyncio.client.AuthorizationV1Api()
rbac_authorization_v1_api = kubernetes_asyncio.client.RbacAuthorizationV1Api()

async def set_operator_cluster_admin():
    global operator_cluster_admin
    try:
        cluster_admin_access_review = await authorization_v1_api.create_self_subject_access_review(
            kubernetes_asyncio.client.V1SelfSubjectAccessReview(
                spec = kubernetes_asyncio.client.V1SelfSubjectAccessReviewSpec(
                    resource_attributes = kubernetes_asyncio.client.V1ResourceAttributes(
                        group='*', resource='*', verb='*'
                    )
                )
            )
        )
        operator_cluster_admin = cluster_admin_access_review.status.allowed
    except kubernetes_asyncio.client.exceptions.ApiException as e:
        pass

asyncio.get_event_loop().run_until_complete(set_operator_cluster_admin())
