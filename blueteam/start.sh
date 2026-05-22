#!/bin/bash
# start.sh — BlueTeam container startup
# ======================================
# Waits for internal dependencies (Cassandra, Elasticsearch) before
# launching supervisord which will then start TheHive and the BlueTeam API.
#
# This avoids TheHive crashing on startup because its storage isn't ready yet.
# supervisord's priority settings handle the rest.

set -e

echo "[start.sh] BlueTeam component starting..."

# ── Wait for Cassandra ────────────────────────────────────────────────────────
echo "[start.sh] Waiting for Cassandra on 127.0.0.1:9042..."
until nc -z 127.0.0.1 9042 2>/dev/null; do
    echo "[start.sh]   Cassandra not ready yet — retrying in 5s"
    sleep 5
done
echo "[start.sh] ✓ Cassandra is up"

# ── Wait for Elasticsearch ────────────────────────────────────────────────────
echo "[start.sh] Waiting for Elasticsearch on 127.0.0.1:9200..."
until curl -sf http://127.0.0.1:9200/_cluster/health >/dev/null 2>&1; do
    echo "[start.sh]   Elasticsearch not ready yet — retrying in 5s"
    sleep 5
done
echo "[start.sh] ✓ Elasticsearch is up"

# ── Wait for TheHive ─────────────────────────────────────────────────────────
echo "[start.sh] Waiting for TheHive on 127.0.0.1:9000..."
until curl -sf http://127.0.0.1:9000/api/status >/dev/null 2>&1; do
    echo "[start.sh]   TheHive not ready yet — retrying in 5s"
    sleep 5
done
echo "[start.sh] ✓ TheHive is up"

echo "[start.sh] All internal services ready. BlueTeam API is live on :8010"
exec "$@"
