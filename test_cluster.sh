#!/usr/bin/env bash
set -euo pipefail

echo "=== Building Docker images ==="
docker compose build

echo "=== Starting cluster ==="
docker compose up -d
sleep 5

echo "=== Check node IDs ==="
for node in node1 node2 node3; do
    echo -n "$node: "
    curl -s "http://localhost:808${node:4:1}/status" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['node_id'][:20], 'peers:', d['peer_count'])"
done

echo "=== Store a file on node1 ==="
echo "Hello dstore cluster!" > /tmp/cluster_test.txt
ROOT=$(docker compose exec -T node1 dstore store /tmp/cluster_test.txt 2>/dev/null)
echo "Root hash: $ROOT"

echo "=== Retrieve from node2 ==="
docker compose exec -T node2 dstore get "$ROOT" -o /tmp/cluster_out.txt 2>/dev/null
docker compose exec -T node2 cat /tmp/cluster_out.txt

echo "=== Get from node3 ==="
# Use IPC-less fallback with bootstrap
docker compose exec -T node3 dstore get "$ROOT" -o /tmp/cluster_out2.txt --addr 0.0.0.0:0 --bootstrap node1:10001 2>/dev/null
docker compose exec -T node3 cat /tmp/cluster_out2.txt

echo ""
echo "=== Cluster test PASS ==="

echo "=== Cleaning up ==="
docker compose down -v
rm -f /tmp/cluster_test.txt
