#!/bin/bash
set -e

echo "Starting Kubesec Agent..."
sudo KUBECONFIG=$HOME/.kube/config ./bin/kubesec-agent -clickhouse localhost > agent_test.log 2>&1 &
AGENT_PID=$!

function cleanup {
    echo "Shutting down agent..."
    sudo kill $AGENT_PID
}
trap cleanup EXIT

echo "Waiting for agent to initialize..."
sleep 10

echo "Querying API..."
curl -v http://localhost:8080/api/workloads -o workloads.json

echo "Response Content:"
cat workloads.json | jq .

echo "Verification complete."
