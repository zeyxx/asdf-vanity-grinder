#!/bin/bash
# ASDF Vanity Grinder - Low Priority Startup Script
# Starts the grinder with minimal resource usage

# Configuration
PORT="${VANITY_PORT:-8080}"
API_KEY="${VANITY_API_KEY:-test-api-key-123}"
MIN_POOL="${VANITY_MIN_POOL:-5}"
THREADS="${VANITY_THREADS:-1}"  # Use only 1 thread for low CPU usage
POOL_FILE="${VANITY_POOL_FILE:-vanity_pool.json}"

# Resource Priority Settings
NICE_LEVEL=19          # Lowest CPU priority (range: -20 to 19)

echo "=========================================="
echo "ASDF Vanity Grinder - Low Priority Mode"
echo "=========================================="
echo "Port:       $PORT"
echo "Threads:    $THREADS (low CPU)"
echo "Nice Level: $NICE_LEVEL (lowest priority)"
echo "Min Pool:   $MIN_POOL"
echo "Pool File:  $POOL_FILE"
echo "=========================================="

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/target/release/asdf-vanity-grinder"

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY"
    echo "Please run: cd $SCRIPT_DIR && cargo build --release"
    exit 1
fi

# Start with low priority
exec nice -n $NICE_LEVEL "$BINARY" pool \
    --file "$POOL_FILE" \
    --port "$PORT" \
    --api-key "$API_KEY" \
    --min-pool "$MIN_POOL" \
    --threads "$THREADS"
