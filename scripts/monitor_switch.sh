#!/bin/bash

set -e

NEXUS="$HOME/nexus"

SNAPSHOT_DIR="$NEXUS/monitoring/snapshots"
TOPOLOGY_DIR="$NEXUS/monitoring/topology"
JETSON_DIR="$NEXUS/monitoring/endpoints"

PREVIOUS="$SNAPSHOT_DIR/current.json"
CURRENT="$SNAPSHOT_DIR/latest.json"

TOPOLOGY="$TOPOLOGY_DIR/current.json"
PREVIOUS_TOPOLOGY="/tmp/nexus-previous-topology.json"

JETSON_IDENTITY="$JETSON_DIR/jetson.json"

echo "===================================="
echo "       NEXUS SWITCH MONITOR"
echo "===================================="
echo

cd "$NEXUS"

# ============================================================
# INITIAL BASELINE
# ============================================================

if [ ! -f "$PREVIOUS" ]; then

    echo "No previous switch snapshot found."
    echo "Creating initial baseline..."
    echo

    python3 -m scripts.agent.switch_info --json \
        > "$CURRENT"

    mv "$CURRENT" "$PREVIOUS"

    mkdir -p "$JETSON_DIR"

    python3 -m scripts.agent.jetson_info --json \
        > "$JETSON_IDENTITY"

    mkdir -p "$TOPOLOGY_DIR"

    python3 -m scripts.agent.network_topology \
        "$PREVIOUS" \
        --save

    echo
    echo "Initial topology baseline created:"
    echo "$TOPOLOGY"
    echo

    exit 0
fi

# ============================================================
# SAVE PREVIOUS TOPOLOGY BEFORE REBUILDING IT
# ============================================================

HAD_PREVIOUS_TOPOLOGY=0

if [ -f "$TOPOLOGY" ]; then
    cp "$TOPOLOGY" "$PREVIOUS_TOPOLOGY"
    HAD_PREVIOUS_TOPOLOGY=1
fi

# ============================================================
# SWITCH COLLECTION
# ============================================================

echo "Previous snapshot:"
echo "$PREVIOUS"
echo

echo "Collecting current switch state..."
echo

python3 -m scripts.agent.switch_info --json \
    > "$CURRENT"

echo
echo "Running switch change detection..."
echo

python3 -m scripts.agent.switch_diff \
    "$PREVIOUS" \
    "$CURRENT" \
    --live

RESULT=$?

if [ "$RESULT" -ne 0 ]; then

    rm -f "$CURRENT"

    echo
    echo "===================================="
    echo "       MONITORING ERROR"
    echo "===================================="
    echo
    echo "Switch change detection returned:"
    echo "$RESULT"

    exit "$RESULT"
fi

# ============================================================
# JETSON ENDPOINT COLLECTION
# ============================================================

echo
echo "Collecting Jetson endpoint identity..."
echo

mkdir -p "$JETSON_DIR"

python3 -m scripts.agent.jetson_info --json \
    > "$JETSON_IDENTITY"

# ============================================================
# BUILD CURRENT TOPOLOGY
# ============================================================

echo
echo "Building current topology..."
echo

python3 -m scripts.agent.network_topology \
    "$CURRENT" \
    --save

# ============================================================
# TOPOLOGY CHANGE DETECTION
# ============================================================

if [ "$HAD_PREVIOUS_TOPOLOGY" -eq 1 ]; then

    echo
    echo "Running topology change detection..."
    echo

    python3 -m scripts.agent.topology_diff \
        "$PREVIOUS_TOPOLOGY" \
        "$TOPOLOGY" \
        --live

    TOPOLOGY_RESULT=$?

    rm -f "$PREVIOUS_TOPOLOGY"

    if [ "$TOPOLOGY_RESULT" -ne 0 ]; then
        echo
        echo "Topology change detection failed."
        exit "$TOPOLOGY_RESULT"
    fi

else

    echo
    echo "No previous topology baseline found."
    echo "Current topology established as baseline."
    echo

fi

# ============================================================
# UPDATE SWITCH SNAPSHOT
# ============================================================

mv "$CURRENT" "$PREVIOUS"

# ============================================================
# EVENT STATE
# ============================================================

echo
echo "===================================="
echo "       EVENT STATE"
echo "===================================="
echo

python3 -m scripts.agent.event_state \
    --monitor-run

# ============================================================
# ALERT ENGINE
# ============================================================

echo
echo "===================================="
echo "       EVENT ALERTS"
echo "===================================="
echo

python3 -m scripts.agent.event_alert

# ============================================================
# JETSON HARDWARE STATE
# ============================================================

echo
echo "===================================="
echo "       JETSON HARDWARE STATE"
echo "===================================="
echo

python3 -m scripts.agent.publish_jetson_state

echo
echo "===================================="
echo "       NEXUS MONITOR COMPLETE"
echo "===================================="
echo
