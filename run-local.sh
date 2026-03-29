#!/bin/bash

set -eo pipefail

OPERATOR_NAMESPACE=${OPERATOR_NAMESPACE:-openshift-oauth-account-operator}
export OPERATOR_NAMESPACE

if oc auth can-i create clusterrole -A >/dev/null; then
    helm template helm/ \
    --include-crds \
    --set deploy=false \
    --set namespace.name=user-namespace-operator \
    --set defaultUserNamespaceConfig.create=false \
    | oc apply -f -
fi

oc project user-namespace-operator

if [[ -d venv ]]; then
  . ./venv/bin/activate
else
  python -m venv ./venv
  . ./venv/bin/activate
  pip install -r dev-requirements.txt
  pip install -r requirements.txt
fi

cd ./operator

exec kopf run \
  --standalone \
  --all-namespaces \
  --liveness=http://0.0.0.0:8080/healthz \
  operator.py
