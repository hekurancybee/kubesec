#!/bin/bash
# ICU.systems - Test Script
# Verifies syscall data is being correctly stored to ClickHouse

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[TEST]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILURES=$((FAILURES + 1)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

FAILURES=0
CAPTURE_DURATION=${1:-15}  # Default 15 seconds

echo ""
log "=========================================="
log "  ICU.systems Integration Tests"
log "=========================================="
echo ""

# Ensure port-forward is running
log "Checking ClickHouse port-forward..."
if ! nc -z localhost 9000 2>/dev/null; then
    log "Starting port-forward..."
    kubectl port-forward svc/clickhouse -n kubesec 9000:9000 &>/dev/null &
    sleep 3
fi

# Truncate existing data
log "Clearing ClickHouse data..."
kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
    --query "TRUNCATE TABLE syscall_events" 2>/dev/null || true

# Start agent in background
log "Starting agent (capture duration: ${CAPTURE_DURATION}s)..."
cd "$PROJECT_DIR"
timeout $CAPTURE_DURATION sudo -E KUBECONFIG=$HOME/.kube/config ./bin/kubesec-agent \
    --clickhouse localhost:9000 --quiet 2>&1 &
AGENT_PID=$!

sleep 3

# Generate activity in demo pods
log "Generating activity in demo pods..."
for i in 1 2 3; do
    kubectl exec -n demo deploy/secure-app -- sh -c "ls -la /; cat /etc/hosts; ps aux; date; env" 2>/dev/null &
    kubectl exec -n demo deploy/audit-app -- sh -c "ls -la /; cat /etc/nginx/nginx.conf; whoami" 2>/dev/null &
    kubectl exec -n demo deploy/unsecure-app -- sh -c "ls -la /tmp; df -h; uptime; id" 2>/dev/null &
    sleep 1
done

# Wait for agent to complete
log "Waiting for capture to complete..."
wait $AGENT_PID 2>/dev/null || true

echo ""
log "=========================================="
log "  Running Tests"
log "=========================================="
echo ""

# Test 1: Check total events > 0
log "Test 1: Events captured..."
TOTAL=$(kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
    --query "SELECT count() FROM syscall_events" 2>/dev/null)
if [[ "$TOTAL" -gt 0 ]]; then
    pass "Total events captured: $TOTAL"
else
    fail "No events captured"
fi

# Test 2: Check kube-system namespace captured
log "Test 2: kube-system namespace..."
KUBE_SYS=$(kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
    --query "SELECT count() FROM syscall_events WHERE namespace = 'kube-system'" 2>/dev/null)
if [[ "$KUBE_SYS" -gt 0 ]]; then
    pass "kube-system events: $KUBE_SYS"
else
    fail "No kube-system events captured"
fi

# Test 3: Check demo namespace captured
log "Test 3: demo namespace..."
DEMO=$(kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
    --query "SELECT count() FROM syscall_events WHERE namespace = 'demo'" 2>/dev/null)
if [[ "$DEMO" -gt 0 ]]; then
    pass "demo namespace events: $DEMO"
else
    fail "No demo namespace events captured"
fi

# Test 4: Check each demo pod
log "Test 4: Individual demo pods..."
for POD in "secure-app" "audit-app" "unsecure-app"; do
    COUNT=$(kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
        --query "SELECT count() FROM syscall_events WHERE namespace = 'demo' AND pod_name LIKE '${POD}%'" 2>/dev/null)
    if [[ "$COUNT" -gt 0 ]]; then
        pass "  $POD: $COUNT unique syscalls"
    else
        fail "  $POD: no syscalls captured"
    fi
done

# Test 5: Check expected syscalls exist
log "Test 5: Expected syscalls present..."
EXPECTED_SYSCALLS=("execve" "read" "write" "openat" "close" "mmap" "futex")
for SYSCALL in "${EXPECTED_SYSCALLS[@]}"; do
    EXISTS=$(kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
        --query "SELECT count() FROM syscall_events WHERE syscall_name = '$SYSCALL'" 2>/dev/null)
    if [[ "$EXISTS" -gt 0 ]]; then
        pass "  syscall '$SYSCALL' captured"
    else
        warn "  syscall '$SYSCALL' not captured (may be OK)"
    fi
done

# Test 6: Check pod names are resolved (not empty)
log "Test 6: Pod names resolved..."
EMPTY_POD=$(kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
    --query "SELECT count() FROM syscall_events WHERE pod_name = ''" 2>/dev/null)
RESOLVED=$(kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
    --query "SELECT count() FROM syscall_events WHERE pod_name != ''" 2>/dev/null)
if [[ "$RESOLVED" -gt 0 ]] && [[ "$EMPTY_POD" -eq 0 || "$EMPTY_POD" -lt "$RESOLVED" ]]; then
    pass "Pod names resolved: $RESOLVED events (unresolved: $EMPTY_POD)"
else
    fail "Pod name resolution issues: resolved=$RESOLVED, empty=$EMPTY_POD"
fi

# Test 7: Check unique syscalls per pod (deduplication working)
log "Test 7: Deduplication working..."
UNIQUE_PER_POD=$(kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
    --query "SELECT pod_name, count() FROM syscall_events WHERE namespace = 'demo' GROUP BY pod_name" 2>/dev/null)
# Each demo pod should have < 100 unique syscalls (not millions of duplicate events)
MAX_PER_POD=$(kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
    --query "SELECT max(c) FROM (SELECT count() as c FROM syscall_events WHERE namespace = 'demo' GROUP BY pod_name)" 2>/dev/null)
if [[ "$MAX_PER_POD" -lt 200 ]]; then
    pass "Deduplication working (max $MAX_PER_POD unique syscalls per pod)"
else
    warn "High syscall count per pod: $MAX_PER_POD (check deduplication)"
fi

# Test 8: Show syscall profiles for demo apps
log "Test 8: Syscall profiles..."
echo ""
kubectl exec -n kubesec deploy/clickhouse -- clickhouse-client --database kubesec \
    --query "SELECT 
        namespace, 
        pod_name, 
        count() as unique_syscalls,
        arrayStringConcat(arraySlice(groupArray(syscall_name), 1, 10), ', ') as sample_syscalls
    FROM syscall_events 
    WHERE namespace = 'demo'
    GROUP BY namespace, pod_name
    FORMAT PrettyCompact" 2>/dev/null || true
echo ""

# Summary
echo ""
log "=========================================="
if [[ $FAILURES -eq 0 ]]; then
    pass "  All tests passed!"
else
    fail "  $FAILURES test(s) failed"
fi
log "=========================================="
echo ""

exit $FAILURES
