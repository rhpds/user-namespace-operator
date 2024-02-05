import asyncio
import kubernetes_asyncio
import os

class UserNamespaceOperator():
    check_interval = int(os.environ.get('CHECK_INTERVAL', 900))
    operator_domain = os.environ.get('OPERATOR_DOMAIN', 'usernamespace.gpte.redhat.com')
    operator_version = os.environ.get('OPERATOR_VERSION', 'v1')
    operator_api_version = f"{operator_domain}/{operator_version}"
    operator_service_account_name = os.environ.get('OPERATOR_SERVICE_ACCOUNT', 'user-namespace-operator')
    operator_cluster_admin = False

    @classmethod
    async def cleanup(cls):
        await cls.api_client.close()
    
    @classmethod
    async def startup(cls, logger):
        if os.path.exists('/run/secrets/kubernetes.io/serviceaccount'):
            kubernetes_asyncio.config.load_incluster_config()
            with open('/run/secrets/kubernetes.io/serviceaccount/namespace') as f:
                cls.operator_namespace = f.read()
        else:
            await kubernetes_asyncio.config.load_kube_config()
            cls.operator_namespace = kubernetes_asyncio.config.list_kube_config_contexts()[1]['context']['namespace']

        cls.api_client = kubernetes_asyncio.client.ApiClient()
        cls.core_v1_api = kubernetes_asyncio.client.CoreV1Api(cls.api_client)
        cls.custom_objects_api = kubernetes_asyncio.client.CustomObjectsApi(cls.api_client)
        cls.authorization_v1_api = kubernetes_asyncio.client.AuthorizationV1Api(cls.api_client)
        cls.rbac_authorization_v1_api = kubernetes_asyncio.client.RbacAuthorizationV1Api(cls.api_client)

        await cls.__set_operator_cluster_admin(logger)

    @classmethod
    async def __set_operator_cluster_admin(cls, logger):
        try:
            cluster_admin_access_review = await cls.authorization_v1_api.create_self_subject_access_review(
                kubernetes_asyncio.client.V1SelfSubjectAccessReview(
                    spec = kubernetes_asyncio.client.V1SelfSubjectAccessReviewSpec(
                        resource_attributes = kubernetes_asyncio.client.V1ResourceAttributes(
                            group='*', resource='*', verb='*'
                        )
                    )
                )
            )
            cls.operator_cluster_admin = cluster_admin_access_review.status.allowed
        except kubernetes_asyncio.client.exceptions.ApiException as e:
            pass

        if cls.operator_cluster_admin:
            logger.info("Running as cluster-admin")
        else:
            logger.info("Running without cluster-admin privileges")
