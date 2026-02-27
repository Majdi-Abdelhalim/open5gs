#!/bin/bash
# ho-extract-messages.sh — Extract SBI and NGAP messages from handover pcap
#
# Usage: ./scripts/ho-extract-messages.sh <pcap_file> [filter]
#
# Extracts and displays inter-PLMN N2 handover SBI messages:
#   - Nsmf_PDUSession (UpdateSMContext, CreateSMContext)
#   - Namf_Communication (CreateUEContext, N2InfoNotify)
#   - NGAP messages (HandoverRequired, HandoverRequest, etc.)
#
# Optional filter: "sbi" | "ngap" | "all" (default: all)

set -euo pipefail

PCAP="${1:?Usage: $0 <pcap_file> [sbi|ngap|all]}"
FILTER="${2:-all}"

if [[ ! -f "$PCAP" ]]; then
    echo "ERROR: File not found: $PCAP" >&2
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=== Inter-PLMN N2 Handover Message Extraction ===${NC}"
echo -e "${CYAN}    PCAP: $PCAP${NC}"
echo -e "${CYAN}    Filter: $FILTER${NC}"
echo ""

# SBI messages (HTTP/2 over TCP)
if [[ "$FILTER" == "all" || "$FILTER" == "sbi" ]]; then
    echo -e "${GREEN}━━━ SBI Messages (Nsmf_PDUSession + Namf_Communication) ━━━${NC}"
    echo ""

    # Extract HTTP/2 requests with relevant paths
    tshark -r "$PCAP" -Y 'http2.headers.path contains "sm-contexts" or http2.headers.path contains "ue-contexts" or http2.headers.path contains "n1-n2-messages" or http2.headers.path contains "n2-info-notify"' \
        -T fields \
        -e frame.number \
        -e frame.time_relative \
        -e ip.src \
        -e ip.dst \
        -e tcp.srcport \
        -e tcp.dstport \
        -e http2.headers.method \
        -e http2.headers.path \
        -e http2.headers.status \
        -e http2.headers.content_type \
        -E header=y \
        -E separator='|' \
        2>/dev/null | column -t -s'|' || echo "(No SBI messages found)"

    echo ""

    # Show hoState values in request bodies
    echo -e "${YELLOW}  hoState values in SBI bodies:${NC}"
    tshark -r "$PCAP" -Y 'http2' \
        -T fields -e frame.number -e frame.time_relative -e http2.data.data \
        2>/dev/null | while IFS=$'\t' read -r frame time data; do
        if [[ -n "$data" ]]; then
            # Look for hoState in hex-decoded data
            decoded=$(echo "$data" | xxd -r -p 2>/dev/null || true)
            if echo "$decoded" | grep -qo '"hoState"'; then
                hostate=$(echo "$decoded" | grep -oP '"hoState"\s*:\s*"[^"]*"' 2>/dev/null || true)
                if [[ -n "$hostate" ]]; then
                    echo "    Frame $frame (${time}s): $hostate"
                fi
            fi
        fi
    done

    echo ""
fi

# NGAP messages
if [[ "$FILTER" == "all" || "$FILTER" == "ngap" ]]; then
    echo -e "${BLUE}━━━ NGAP Messages ━━━${NC}"
    echo ""

    # Extract NGAP handover-related messages
    tshark -r "$PCAP" -Y 'ngap' \
        -T fields \
        -e frame.number \
        -e frame.time_relative \
        -e ip.src \
        -e ip.dst \
        -e ngap.procedureCode \
        -e ngap.value \
        -E header=y \
        -E separator='|' \
        2>/dev/null | head -50 | column -t -s'|' || echo "(No NGAP messages found)"

    echo ""
fi

# Summary statistics
echo -e "${CYAN}━━━ Summary ━━━${NC}"
echo -n "  Total frames: "
tshark -r "$PCAP" -T fields -e frame.number 2>/dev/null | wc -l
echo -n "  SBI (HTTP/2): "
tshark -r "$PCAP" -Y 'http2' -T fields -e frame.number 2>/dev/null | wc -l
echo -n "  NGAP: "
tshark -r "$PCAP" -Y 'ngap' -T fields -e frame.number 2>/dev/null | wc -l
echo -n "  PFCP: "
tshark -r "$PCAP" -Y 'pfcp' -T fields -e frame.number 2>/dev/null | wc -l
echo -n "  GTP-U: "
tshark -r "$PCAP" -Y 'gtp' -T fields -e frame.number 2>/dev/null | wc -l
echo ""

# Time range
echo -n "  Duration: "
tshark -r "$PCAP" -T fields -e frame.time_relative 2>/dev/null | tail -1 | xargs -I{} echo "{}s"
