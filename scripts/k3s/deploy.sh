#!/usr/bin/env bash
# Deploy the MDRJ-DAG demo cluster to k3s/k3d.
# Idempotent: safe to re-run.
#
# Prereqs on the host:
#   - docker
#   - k3d (will install k3s-in-Docker; gives kubectl too)
#   - openssl
#
# Usage:
#   scripts/k3s/deploy.sh [--cluster-name mdrj] [--replicas 5] [--image mdrj-dag:demo]
set -euo pipefail

CLUSTER_NAME=mdrj
REPLICAS=5
IMAGE=mdrj-dag:demo
NAMESPACE=mdrj
PORT_DASHBOARD=30901

while [[ $# -gt 0 ]]; do
  case $1 in
    --cluster-name) CLUSTER_NAME=$2; shift 2;;
    --replicas) REPLICAS=$2; shift 2;;
    --image) IMAGE=$2; shift 2;;
    *) echo "unknown: $1"; exit 2;;
  esac
done

echo "=== MDRJ-DAG demo deploy ==="
echo "cluster=${CLUSTER_NAME}  replicas=${REPLICAS}  image=${IMAGE}"
echo ""

# 1. Cluster up
if ! k3d cluster list "$CLUSTER_NAME" 2>/dev/null | grep -q "$CLUSTER_NAME"; then
  echo "[1/6] Creating k3d cluster..."
  k3d cluster create "$CLUSTER_NAME" \
    --servers 1 --agents 2 \
    -p "${PORT_DASHBOARD}:${PORT_DASHBOARD}@server:0"
else
  echo "[1/6] Cluster ${CLUSTER_NAME} already exists"
fi

# 2. Build image and import into cluster
echo "[2/6] Building docker image ${IMAGE}"
docker build -t "$IMAGE" .

echo "[3/6] Importing image into k3d"
k3d image import "$IMAGE" -c "$CLUSTER_NAME"

# 3. Namespace
echo "[4/6] Applying namespace + manifests"
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/services.yaml

# 4. Secret (generated each deploy; rotate if you re-run)
if ! kubectl -n "$NAMESPACE" get secret mdrj-secrets >/dev/null 2>&1; then
  echo "[5/6] Generating mdrj-secrets"
  kubectl -n "$NAMESPACE" create secret generic mdrj-secrets \
    --from-literal=hmac-key="$(openssl rand -hex 32)"
else
  echo "[5/6] mdrj-secrets exists; leaving as-is"
fi

# 5. StatefulSet (with REPLICAS substituted)
echo "[6/6] Applying StatefulSet with replicas=${REPLICAS}"
sed "s/replicas: 5/replicas: ${REPLICAS}/" deploy/k8s/statefulset.yaml | kubectl apply -f -

echo ""
echo "Waiting for pods to be ready..."
kubectl -n "$NAMESPACE" rollout status statefulset/mdrj --timeout=120s

echo ""
echo "=== Cluster up. Useful commands: ==="
echo "  kubectl -n ${NAMESPACE} get pods -o wide"
echo "  kubectl -n ${NAMESPACE} get pvc"
echo "  curl http://localhost:${PORT_DASHBOARD}/status"
echo "  curl http://localhost:${PORT_DASHBOARD}/metrics/dashboard  # open in browser"
echo ""
echo "  scripts/k3s/load_gen.py --pods localhost:${PORT_DASHBOARD} --rate 20 --duration 60"
echo "  scripts/k3s/chaos.sh --interval 30 --rounds 5"
echo "  scripts/k3s/tamper_demo.sh --pod mdrj-2"
