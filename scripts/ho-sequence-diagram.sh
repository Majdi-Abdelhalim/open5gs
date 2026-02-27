#!/bin/bash
# ho-sequence-diagram.sh — Generate Mermaid sequence diagram from handover pcap
#
# Usage: ./scripts/ho-sequence-diagram.sh <pcap_file> [output.md]
#
# Generates a Mermaid sequence diagram showing the inter-PLMN N2 handover
# message flow between source gNB, S-AMF, T-AMF, V-SMF, H-SMF, V-UPF, PSA-UPF.
#
# Output is a Markdown file with embedded Mermaid diagram.

set -euo pipefail

PCAP="${1:?Usage: $0 <pcap_file> [output.md]}"
OUTPUT="${2:-$(basename "$PCAP" .pcap)-sequence.md}"

if [[ ! -f "$PCAP" ]]; then
    echo "ERROR: File not found: $PCAP" >&2
    exit 1
fi

# IP address to entity mapping (customize for your setup)
declare -A IP_NAME=(
    ["127.0.0.1"]="S-gNB"
    ["127.0.0.2"]="T-gNB"
    ["127.0.1.5"]="S-AMF"
    ["127.0.2.5"]="T-AMF"
    ["127.0.1.4"]="H-SMF"
    ["127.0.2.4"]="V-SMF"
    ["127.0.1.7"]="PSA-UPF"
    ["127.0.2.7"]="V-UPF"
    ["127.0.1.200"]="SCP1"
    ["127.0.2.200"]="SCP2"
    ["127.0.1.250"]="SEPP1"
    ["127.0.2.250"]="SEPP2"
)

resolve_name() {
    local ip="$1"
    echo "${IP_NAME[$ip]:-$ip}"
}

# Start building the Mermaid diagram
cat > "$OUTPUT" << 'HEADER'
# Inter-PLMN N2 Handover Sequence Diagram

Generated from pcap analysis.

```mermaid
sequenceDiagram
    participant SgNB as S-gNB
    participant SAMF as S-AMF/H-AMF
    participant SEPP as SEPP1↔SEPP2
    participant TAMF as T-AMF/V-AMF
    participant VSMF as V-SMF
    participant HSMF as H-SMF
    participant VUPF as V-UPF
    participant PSAUPF as PSA-UPF
    participant TgNB as T-gNB

HEADER

# Extract HTTP/2 and NGAP events in order
tmpfile=$(mktemp)
trap "rm -f $tmpfile" EXIT

tshark -r "$PCAP" \
    -T fields \
    -e frame.number \
    -e frame.time_relative \
    -e ip.src \
    -e ip.dst \
    -e ngap.procedureCode \
    -e http2.headers.method \
    -e http2.headers.path \
    -e http2.headers.status \
    -e pfcp.msg_type \
    -E separator=$'\t' \
    2>/dev/null > "$tmpfile"

# Process each frame into Mermaid arrows
prev_ts=""
while IFS=$'\t' read -r frame ts src dst ngap_proc http_method http_path http_status pfcp_type; do
    src_name=$(resolve_name "$src")
    dst_name=$(resolve_name "$dst")
    
    label=""
    arrow="->>+"

    # NGAP messages
    if [[ -n "$ngap_proc" ]]; then
        case "$ngap_proc" in
            0) label="HandoverRequired/Command" ;;
            1) label="HandoverRequest/Ack" ;;
            41) label="HandoverNotify" ;;
            40) label="PathSwitchRequest" ;;
            46) label="UEContextRelease" ;;
            14) label="InitialContextSetup" ;;
            21) label="NGSetup" ;;
            15) label="InitialUEMessage" ;;
            *) label="NGAP($ngap_proc)" ;;
        esac
    fi

    # HTTP/2 messages
    if [[ -n "$http_method" && -n "$http_path" ]]; then
        # Extract last path component
        path_short=$(echo "$http_path" | sed 's|.*/||')
        if echo "$http_path" | grep -q "sm-contexts"; then
            if echo "$http_path" | grep -q "modify"; then
                label="UpdateSMContext"
            elif [[ "$http_method" == "POST" ]]; then
                label="CreateSMContext"
            elif [[ "$http_method" == "DELETE" ]]; then
                label="ReleaseSMContext"
            else
                label="SMContext($http_method)"
            fi
        elif echo "$http_path" | grep -q "ue-contexts"; then
            if echo "$http_path" | grep -q "transfer"; then
                label="UEContextTransfer"
            elif [[ "$http_method" == "POST" ]] || [[ "$http_method" == "PUT" ]]; then
                label="CreateUEContext"
            else
                label="UEContext($http_method)"
            fi
        elif echo "$http_path" | grep -q "n2-info-notify"; then
            label="N2InfoNotify"
        elif echo "$http_path" | grep -q "n1-n2"; then
            label="N1N2MessageTransfer"
        fi
    fi

    # HTTP/2 responses (status only, no method)
    if [[ -z "$http_method" && -n "$http_status" ]]; then
        label="${http_status} response"
        arrow="-->>"
    fi

    # PFCP messages
    if [[ -n "$pfcp_type" ]]; then
        case "$pfcp_type" in
            50) label="PFCP Session Establishment Req" ;;
            51) label="PFCP Session Establishment Resp" ;;
            52) label="PFCP Session Modification Req" ;;
            53) label="PFCP Session Modification Resp" ;;
            54) label="PFCP Session Deletion Req" ;;
            55) label="PFCP Session Deletion Resp" ;;
            56) label="PFCP Session Report Req" ;;
            57) label="PFCP Session Report Resp" ;;
            *) label="PFCP($pfcp_type)" ;;
        esac
    fi

    # Skip if no meaningful label
    if [[ -z "$label" ]]; then
        continue
    fi

    # Map IP-based names to Mermaid participants
    mermaid_src="$src_name"
    mermaid_dst="$dst_name"
    
    # Normalize to participant names
    for name in SgNB TgNB SAMF TAMF VSMF HSMF VUPF PSAUPF SEPP; do
        case "$src_name" in
            "S-gNB") mermaid_src="SgNB" ;;
            "T-gNB") mermaid_dst="TgNB" ;;
            "S-AMF") mermaid_src="SAMF" ;;
            "T-AMF") mermaid_src="TAMF" ;;
            "V-SMF") mermaid_src="VSMF" ;;
            "H-SMF") mermaid_src="HSMF" ;;
            "V-UPF") mermaid_src="VUPF" ;;
            "PSA-UPF") mermaid_src="PSAUPF" ;;
            "SCP1"|"SCP2") mermaid_src="SEPP" ;;
            "SEPP1"|"SEPP2") mermaid_src="SEPP" ;;
        esac
    done
    
    case "$dst_name" in
        "S-gNB") mermaid_dst="SgNB" ;;
        "T-gNB") mermaid_dst="TgNB" ;;
        "S-AMF") mermaid_dst="SAMF" ;;
        "T-AMF") mermaid_dst="TAMF" ;;
        "V-SMF") mermaid_dst="VSMF" ;;
        "H-SMF") mermaid_dst="HSMF" ;;
        "V-UPF") mermaid_dst="VUPF" ;;
        "PSA-UPF") mermaid_dst="PSAUPF" ;;
        "SCP1"|"SCP2") mermaid_dst="SEPP" ;;
        "SEPP1"|"SEPP2") mermaid_dst="SEPP" ;;
        *) mermaid_dst="$dst_name" ;;
    esac

    # Skip self-loops
    if [[ "$mermaid_src" == "$mermaid_dst" ]]; then
        continue
    fi

    echo "    ${mermaid_src}${arrow}${mermaid_dst}: #${frame} ${label} (${ts}s)" >> "$OUTPUT"

done < "$tmpfile"

# Close the Mermaid block
echo '```' >> "$OUTPUT"

echo "Sequence diagram written to: $OUTPUT"
echo "View with any Mermaid-compatible renderer (VS Code, GitHub, etc.)"
