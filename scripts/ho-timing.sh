#!/bin/bash
# ho-timing.sh — Measure inter-PLMN N2 handover timing from pcap
#
# Usage: ./scripts/ho-timing.sh <pcap_file>
#
# Measures timing of key handover phases:
#   Phase 1: HandoverRequired → HandoverRequest (AMF processing + CreateUEContext)
#   Phase 2: HandoverRequest → HandoverRequestAck (target gNB processing)
#   Phase 3: HandoverRequestAck → HandoverCommand (SMF UpdateSMContext PREPARED)
#   Phase 4: HandoverCommand → HandoverNotify (UE moves to target)
#   Phase 5: HandoverNotify → Data path switched (PFCP + V-SMF COMPLETED)

set -euo pipefail

PCAP="${1:?Usage: $0 <pcap_file>}"

if [[ ! -f "$PCAP" ]]; then
    echo "ERROR: File not found: $PCAP" >&2
    exit 1
fi

echo "=== Inter-PLMN N2 Handover Timing Analysis ==="
echo "    PCAP: $PCAP"
echo ""

# Extract all frames with timestamps
tmpdir=$(mktemp -d)
trap "rm -rf $tmpdir" EXIT

# Get all HTTP/2 and NGAP frames with timestamps
tshark -r "$PCAP" -T fields \
    -e frame.number \
    -e frame.time_epoch \
    -e frame.time_relative \
    -e ip.src \
    -e ip.dst \
    -e ngap.procedureCode \
    -e http2.headers.path \
    -e http2.headers.method \
    -e http2.headers.status \
    -E separator=$'\t' \
    2>/dev/null > "$tmpdir/all_frames.tsv"

# Find key handover events by NGAP procedure codes
# 0=HandoverPreparation (HandoverRequired/Command)
# 1=HandoverResourceAllocation (HandoverRequest/Ack/Failure)
# 41=HandoverNotification (HandoverNotify)
# 40=PathSwitchRequest

echo "--- Key NGAP Events ---"
tshark -r "$PCAP" -Y 'ngap.procedureCode == 0 or ngap.procedureCode == 1 or ngap.procedureCode == 41 or ngap.procedureCode == 40' \
    -T fields \
    -e frame.number \
    -e frame.time_relative \
    -e ip.src \
    -e ip.dst \
    -e ngap.procedureCode \
    -E separator=$'\t' \
    -E header=y \
    2>/dev/null | column -t || echo "(No NGAP handover events found)"

echo ""

echo "--- Key SBI Events (sm-contexts, ue-contexts) ---"
tshark -r "$PCAP" -Y 'http2.headers.path contains "sm-contexts" or http2.headers.path contains "ue-contexts"' \
    -T fields \
    -e frame.number \
    -e frame.time_relative \
    -e ip.src \
    -e ip.dst \
    -e http2.headers.method \
    -e http2.headers.path \
    -e http2.headers.status \
    -E separator=$'\t' \
    -E header=y \
    2>/dev/null | column -t || echo "(No SBI events found)"

echo ""

echo "--- PFCP Session Events ---"
tshark -r "$PCAP" -Y 'pfcp.msg_type == 56 or pfcp.msg_type == 57 or pfcp.msg_type == 52 or pfcp.msg_type == 53' \
    -T fields \
    -e frame.number \
    -e frame.time_relative \
    -e ip.src \
    -e ip.dst \
    -e pfcp.msg_type \
    -E separator=$'\t' \
    -E header=y \
    2>/dev/null | column -t || echo "(No PFCP events found)"

echo ""

# Calculate overall timing
first_ts=$(tshark -r "$PCAP" -T fields -e frame.time_relative 2>/dev/null | head -1)
last_ts=$(tshark -r "$PCAP" -T fields -e frame.time_relative 2>/dev/null | tail -1)
echo "--- Overall ---"
echo "  First frame: ${first_ts}s"
echo "  Last frame:  ${last_ts}s"
if command -v bc &>/dev/null; then
    duration=$(echo "$last_ts - $first_ts" | bc 2>/dev/null || echo "N/A")
    echo "  Duration:    ${duration}s"
fi
