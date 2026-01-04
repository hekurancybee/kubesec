#!/bin/bash
# ICU.systems - Reset Script
# 
# Usage:
#   ./scripts/reset.sh          # Full reset (clean + rebuild + redeploy)
#   ./scripts/reset.sh --delete # Delete everything completely
#   ./scripts/reset.sh --init   # Initialize from scratch (first time setup)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() { echo -e "${BLUE}[ICU]${NC} $1"; }
success() { echo -e "${GREEN}[ICU]${NC} $1"; }
warn() { echo -e "${YELLOW}[ICU]${NC} $1"; }
error() { echo -e "${RED}[ICU]${NC} $1"; }

MODE="reset"  # Default mode
if [[ "$1" == "--delete" ]]; then
    MODE="delete"
elif [[ "$1" == "--init" ]]; then
    MODE="init"
fi

# ============================================================================
# DELETE MODE - Remove everything completely
# ============================================================================
if [[ "$MODE" == "delete" ]]; then
    log "=========================================="
    log "  ICU.systems - DELETE ALL"
    log "=========================================="
    
    log "Stopping running processes..."
    pkill -f "kubesec-agent" 2>/dev/null || true
    pkill -f "kubectl port-forward.*clickhouse" 2>/dev/null || true
    
    log "Deleting demo namespace..."
    kubectl delete namespace demo --ignore-not-found=true --wait=true 2>/dev/null || true
    
    log "Deleting kubesec namespace..."
    kubectl delete namespace kubesec --ignore-not-found=true --wait=true 2>/dev/null || true
    
    success "=========================================="
    success "  Everything deleted!"
    success "=========================================="
    success "Run './scripts/reset.sh --init' to set up from scratch"
    exit 0
fi

# ============================================================================
# INIT MODE - First time setup from scratch
# ============================================================================
if [[ "$MODE" == "init" ]]; then
    log "=========================================="
    log "  ICU.systems - INITIALIZE FROM SCRATCH"
    log "=========================================="
    
    # Step 1: Stop any running processes
    log "Stopping running processes..."
    pkill -f "kubesec-agent" 2>/dev/null || true
    pkill -f "kubectl port-forward.*clickhouse" 2>/dev/null || true
    sleep 1
    
    # Step 2: Clean up any existing namespaces
    log "Cleaning existing namespaces..."
    kubectl delete namespace demo --ignore-not-found=true --wait=true 2>/dev/null || true
    kubectl delete namespace kubesec --ignore-not-found=true --wait=true 2>/dev/null || true
    sleep 3
    
    # Step 3: Build the agent
    log "Building agent..."
    cd "$PROJECT_DIR"
    go build -o bin/kubesec-agent ./cmd/agent
    success "Agent built: bin/kubesec-agent"
    
    # Step 4: Deploy ClickHouse
    log "Deploying ClickHouse..."
    kubectl apply -f "$PROJECT_DIR/deploy/clickhouse.yaml"
    
    log "Waiting for ClickHouse to be ready..."
    kubectl wait --for=condition=ready pod -l app=clickhouse -n kubesec --timeout=120s
    sleep 5
    
    # Step 5: Create ClickHouse schema
    log "Creating ClickHouse schema..."
    kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client \
        --query "CREATE DATABASE IF NOT EXISTS kubesec"
    
    kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client \
        --database kubesec --query "
        CREATE TABLE IF NOT EXISTS syscall_events (
            timestamp DateTime64(3),
            namespace String,
            pod_name String,
            container String,
            pid UInt32,
            tid UInt32,
            syscall_nr UInt32,
            syscall_name String,
            comm String,
            cgroup_id UInt64,
            node_name String
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMMDD(timestamp)
        ORDER BY (namespace, pod_name, timestamp)
    "
    
    kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client \
        --database kubesec --query "
        CREATE TABLE IF NOT EXISTS workloads (
            kind String,
            namespace String,
            name String,
            pod_template_hash String,
            secure Bool,
            mode String,
            training_period_seconds UInt32,
            training_started DateTime64(3),
            training_completed DateTime64(3),
            syscall_allowlist Array(String),
            updated_at DateTime64(3),
            updated_by String
        ) ENGINE = ReplacingMergeTree(updated_at)
        ORDER BY (kind, namespace, name)
    "
    success "ClickHouse schema created (syscall_events + workloads)"
    
    # Step 6: Deploy demo apps
    log "Deploying demo apps..."
    kubectl apply -f "$PROJECT_DIR/deploy/example-app.yaml"
    
    log "Waiting for demo pods to be ready..."
    sleep 10
    kubectl wait --for=condition=ready pod -l app=secure-app -n demo --timeout=60s 2>/dev/null || true
    kubectl wait --for=condition=ready pod -l app=audit-app -n demo --timeout=60s 2>/dev/null || true
    kubectl wait --for=condition=ready pod -l app=unsecure-app -n demo --timeout=60s 2>/dev/null || true
    
    # Step 7: Start port-forward
    log "Starting ClickHouse port-forward..."
    kubectl port-forward svc/clickhouse -n kubesec 9000:9000 &>/dev/null &
    PORT_FWD_PID=$!
    sleep 2
    
    # Step 8: Summary
    echo ""
    success "=========================================="
    success "  ICU.systems Initialized!"
    success "=========================================="
    echo ""
    kubectl get pods -n kubesec
    echo ""
    kubectl get pods -n demo
    echo ""
    log "Port-forward PID: $PORT_FWD_PID"
    echo ""
    success "Ready to run agent:"
    echo "  sudo -E KUBECONFIG=\$HOME/.kube/config ./bin/kubesec-agent --clickhouse localhost:9000"
    exit 0
fi

# ============================================================================
# RESET MODE (default) - Full cleanup, rebuild, and redeploy
# ============================================================================
log "=========================================="
log "  ICU.systems - FULL RESET"
log "=========================================="

# Step 1: Stop running processes
log "Stopping running processes..."
pkill -f "kubesec-agent" 2>/dev/null || true
pkill -f "kubectl port-forward.*clickhouse" 2>/dev/null || true
sleep 1

# Step 2: Delete namespaces
log "Deleting namespaces..."
kubectl delete namespace demo --ignore-not-found=true --wait=true 2>/dev/null || true
kubectl delete namespace kubesec --ignore-not-found=true --wait=true 2>/dev/null || true
sleep 3

# Step 3: Build agent
log "Building agent..."
cd "$PROJECT_DIR"
go build -o bin/kubesec-agent ./cmd/agent
success "Agent built: bin/kubesec-agent"

# Step 4: Deploy ClickHouse
log "Redeploying ClickHouse..."
kubectl apply -f "$PROJECT_DIR/deploy/clickhouse.yaml"

log "Waiting for ClickHouse to be ready..."
kubectl wait --for=condition=ready pod -l app=clickhouse -n kubesec --timeout=120s
sleep 5

# Step 5: Create ClickHouse schema
log "Creating ClickHouse schema..."
kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client \
    --query "CREATE DATABASE IF NOT EXISTS kubesec"

kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client \
    --database kubesec --query "
    CREATE TABLE IF NOT EXISTS syscall_events (
        timestamp DateTime64(3),
        namespace String,
        pod_name String,
        container String,
        pid UInt32,
        tid UInt32,
        syscall_nr UInt32,
        syscall_name String,
        comm String,
        cgroup_id UInt64,
        node_name String
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMMDD(timestamp)
    ORDER BY (namespace, pod_name, timestamp)
"

kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client \
    --database kubesec --query "
    CREATE TABLE IF NOT EXISTS workloads (
        kind String,
        namespace String,
        name String,
        pod_template_hash String,
        secure Bool,
        mode String,
        training_period_seconds UInt32,
        training_started DateTime64(3),
        training_completed DateTime64(3),
        syscall_allowlist Array(String),
        updated_at DateTime64(3),
        updated_by String
    ) ENGINE = ReplacingMergeTree(updated_at)
    ORDER BY (kind, namespace, name)
"
success "ClickHouse schema created (syscall_events + workloads)"

# Step 6: Deploy demo apps
log "Deploying demo apps..."
kubectl apply -f "$PROJECT_DIR/deploy/example-app.yaml"

log "Waiting for demo pods to be ready..."
sleep 10
kubectl wait --for=condition=ready pod -l app=secure-app -n demo --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=ready pod -l app=audit-app -n demo --timeout=60s 2>/dev/null || true
kubectl wait --for=condition=ready pod -l app=unsecure-app -n demo --timeout=60s 2>/dev/null || true

# Step 7: Start port-forward
log "Starting ClickHouse port-forward..."
kubectl port-forward svc/clickhouse -n kubesec 9000:9000 &>/dev/null &
PORT_FWD_PID=$!
sleep 2

# Step 8: Verify
echo ""
success "=========================================="
success "  Reset Complete!"
success "=========================================="
echo ""
kubectl get pods -n kubesec
echo ""
kubectl get pods -n demo
echo ""
kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
    --query "SELECT count() as events FROM syscall_events" 2>/dev/null || echo "Events: 0"
echo ""
log "Port-forward PID: $PORT_FWD_PID"
echo ""
success "Ready to run agent:"
echo "  sudo -E KUBECONFIG=\$HOME/.kube/config ./bin/kubesec-agent --clickhouse localhost:9000"
echo ""
success "Run tests:"
echo "  ./scripts/test.sh"
