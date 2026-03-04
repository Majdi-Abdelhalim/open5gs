# Inter-PLMN N2 Handover — Pcap Verification Guide

This document describes the expected message flow during inter-PLMN N2 handover
and what to look for in pcap captures to verify correct operation.

## Prerequisites

- **LBO tests**: In [configs/examples/gnb-999-70-ue-001-01.yaml.in](../configs/examples/gnb-999-70-ue-001-01.yaml.in),
  ensure `test.subscriber.lbo_roaming_allowed: true`. Without this, PDU sessions
  will be home-routed instead of local-breakout, changing the handover behavior.
- **HR tests**: The HR test suite uses subscribers with `lbo_roaming_allowed: false`,
  which causes PDU sessions to be home-routed through H-SMF/V-SMF.

## Test Environment Network Topology

| Component         | Home PLMN (999-70)  | Visiting PLMN (001-01) |
|-------------------|----------------------|------------------------|
| AMF               | 127.0.1.5:80         | 127.0.2.5:80           |
| SCP               | 127.0.1.200:7777     | 127.0.2.200:7777       |
| SEPP (SBI)        | 127.0.1.250:7777     | 127.0.2.250:7777       |
| SEPP (N32)        | 127.0.1.251:7777     | 127.0.2.252:7777       |
| NRF               | 127.0.1.10:80        | 127.0.2.10:80          |
| SMF               | 127.0.1.4:80         | 127.0.2.4:80           |
| UDR               | 127.0.1.20:80        | —                      |
| UDM               | 127.0.1.12:80        | —                      |
| Source gNB (SCTP) | 127.0.0.2            | —                      |
| Target gNB (SCTP) | —                    | 127.0.0.3              |

### Understanding 127.0.0.1 in the pcap

All NF processes run on the same machine using loopback addresses. There are
two transport protocols with different source-IP behavior:

- **SCTP (NGAP)**: The test explicitly binds gNB SCTP sockets to specific
  addresses (`127.0.0.2` for source gNB, `127.0.0.3` for target gNB). AMFs
  bind to their configured addresses (`127.0.1.5`, `127.0.2.5`). Therefore
  **NGAP messages always show correct src and dst IPs**.

- **TCP (HTTP/2 SBI)**: NFs listen on their configured addresses but when
  making outgoing TCP connections, the Linux kernel selects `127.0.0.1` as
  the source address (the default for loopback). Therefore, **all SBI request
  messages show `127.0.0.1` as the source IP**. The destination IP identifies
  which NF receives the message. SBI responses show the NF's configured IP as
  source (e.g., `127.0.2.5 → 127.0.0.1`).

**Key rule**: For SBI messages, identify the sender by context (which NF
initiated the HTTP/2 request) and the receiver by the destination IP.

All SBI traffic on port 80 and 7777 uses HTTP/2. To decode properly in
tshark, add: `-d tcp.port==80,http2 -d tcp.port==7777,http2`

## NGAP Procedure Codes Reference

| Code | Procedure                           |
|------|-------------------------------------|
| 21   | NGSetupRequest / NGSetupResponse    |
| 15   | InitialUEMessage                    |
| 4    | DownlinkNASTransport                |
| 46   | UplinkNASTransport                  |
| 14   | InitialContextSetupRequest/Response |
| 44   | UERadioCapabilityInfoIndication     |
| 29   | PDUSessionResourceSetupRequest/Resp |
| 12   | HandoverRequired / HandoverCommand  |
| 13   | HandoverRequest / HandoverRequestAck|
| 11   | HandoverNotify                      |
| 41   | UEContextReleaseCommand / Complete  |
| 42   | UEContextReleaseRequest             |
| 47   | UplinkRANStatusTransfer             |
| 48   | DownlinkRANStatusTransfer           |

## Capturing

```bash
# Start capture on loopback
sudo tcpdump -i lo -s 0 -w handover_test.pcap

# In another terminal, run the tests
sudo ./build/tests/roaming/roaming \
    -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml \
    n2-handover-test -v test1 -e info

# Stop capture with Ctrl-C
```

## Master Filter: Full Handover Message Sequence

This single filter shows all handover-relevant messages (NGAP + key SBI +
PFCP + GTP-U) in chronological order, excluding NRF discovery, UDR, UDM, PCF,
BSF, and AUSF background traffic:

```bash
tshark -r handover_test.pcap \
    -d tcp.port==80,http2 -d tcp.port==7777,http2 \
    -Y 'ngap || pfcp || gtp || (http2.headers.path and (http2.headers.path contains "namf-comm" or http2.headers.path contains "nsmf-pdusession"))' \
    -T fields -e frame.number -e ip.src -e ip.dst -e tcp.dstport \
    -e ngap.procedureCode -e pfcp.msg_type -e gtp.message_type \
    -e http2.headers.method -e http2.headers.path
```

## Additional Useful Filters

```bash
# Only NGAP handover messages (procedure codes 12, 13, 11)
tshark -r handover_test.pcap \
    -Y 'ngap.procedureCode == 12 || ngap.procedureCode == 13 || ngap.procedureCode == 11' \
    -T fields -e frame.number -e ip.src -e ip.dst -e ngap.procedureCode

# Only CreateUEContext hops (the 5-hop SEPP chain)
tshark -r handover_test.pcap \
    -d tcp.port==80,http2 -d tcp.port==7777,http2 \
    -Y 'http2.headers.path contains "/namf-comm/v1/ue-contexts/imsi" and http2.headers.method == "POST" and not http2.headers.path contains "n1-n2" and not http2.headers.path contains "n2-info"' \
    -T fields -e frame.number -e ip.src -e ip.dst -e tcp.dstport

# Only N2InfoNotify hops (the 5-hop SEPP chain, reverse direction)
tshark -r handover_test.pcap \
    -d tcp.port==80,http2 -d tcp.port==7777,http2 \
    -Y 'http2.headers.path contains "n2-info-notify"' \
    -T fields -e frame.number -e ip.src -e ip.dst -e tcp.dstport

# V-SMF → H-SMF SBI traffic through SEPP (HR only)
tshark -r handover_test.pcap \
    -d tcp.port==80,http2 -d tcp.port==7777,http2 \
    -Y 'http2.headers.path contains "pdu-sessions" and (http2.headers.method == "POST" or http2.headers.method == "PATCH")' \
    -T fields -e frame.number -e ip.src -e ip.dst -e tcp.dstport -e http2.headers.method -e http2.headers.path

# PFCP traffic (V-UPF and PSA-UPF N4 sessions)
tshark -r handover_test.pcap \
    -Y 'pfcp' \
    -T fields -e frame.number -e ip.src -e ip.dst -e pfcp.msg_type

# GTP-U traffic (post-handover data verification)
tshark -r handover_test.pcap \
    -Y 'gtp' \
    -T fields -e frame.number -e ip.src -e ip.dst -e gtp.message_type -e gtp.teid

# Post-handover GTP-U only (filter by V-UPF address)
tshark -r handover_test.pcap \
    -Y 'gtp and (ip.addr == 127.0.2.7)' \
    -T fields -e frame.number -e ip.src -e ip.dst -e gtp.message_type -e gtp.teid
```

---

## Expected Message Flow for test1 (Direct Forwarding Cross-PLMN)

Below is the complete sequence with **exact src → dst IPs** for every message.

### Phase 1: Infrastructure Setup & Registration

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 21  | NGSetupRequest (src gNB → Home AMF) |
| 2 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 21  | NGSetupResponse               |
| 3 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 21  | NGSetupRequest (tgt gNB → Visiting AMF) |
| 4 | 127.0.2.5   | 127.0.0.3   | SCTP | NGAP 21  | NGSetupResponse               |
| 5 | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 15  | InitialUEMessage              |
| 6 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP  4  | DownlinkNASTransport (Auth)   |
| 7 | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 46  | UplinkNASTransport (Auth resp)|
|...|             |             |      |          | *(several more NAS exchanges)*|
| n | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 14  | InitialContextSetupRequest    |
|n+1| 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 44  | UERadioCapabilityInfoInd      |
|n+2| 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 14  | InitialContextSetupResponse   |

### Phase 1b: PDU Session Establishment

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| a | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 46  | UL NAS: PDU Session Est Req   |
| b | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP  4  | DL NAS: PDU Session Auth      |
| c | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 46  | UL NAS: PDU Session Auth Resp |
| d | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST /nsmf-pdusession/v1/sm-contexts (AMF→SCP) |
| e | 127.0.0.1   | 127.0.1.4   |  80  | SBI      | POST /nsmf-pdusession/v1/sm-contexts (SCP→SMF)  |
|...|             |             |      |          | *(SMF creates session, calls back N1N2)* |
| f | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../n1-n2-messages (SMF→SCP) |
| g | 127.0.0.1   | 127.0.1.5   |  80  | SBI      | POST .../n1-n2-messages (SCP→AMF) |
| h | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 29  | PDUSessionResourceSetupRequest|
| i | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 29  | PDUSessionResourceSetupResp   |

### Phase 2: Handover Preparation

#### Step 2a: HandoverRequired

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 12  | **HandoverRequired** (src gNB → Home AMF) |

**What to verify**: Src IP is `127.0.0.2` (not `127.0.0.1`). Contains Target
ID with visiting PLMN cell info. SourceToTarget-TransparentContainer should
NOT show "Malformed Packet" in Wireshark.

#### Step 2b: PDU Session Context Modification

<!-- Immediately after HandoverRequired, the Home AMF sends a PDU session modify to
the SMF to prepare for handover. For LBO, this triggers indirect-forwarding
tunnel setup (or release, depending on the session state). -->

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 2 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST /nsmf-pdusession/v1/sm-contexts/{id}/modify (AMF→SCP) |
| 3 | 127.0.0.1   | 127.0.1.4   |  80  | SBI      | POST /nsmf-pdusession/v1/sm-contexts/{id}/modify (SCP→SMF) |

**What to verify**: This appears as `sm-contexts/1/modify` (or whichever
session ID). Both hops show `127.0.0.1` as source (TCP origin).

#### Step 2c: NRF Discovery for Target AMF (through SEPP)

<!-- Before sending CreateUEContext, the Home SCP must discover the target AMF in the
visiting PLMN. This NRF discovery itself goes through SEPP since the target PLMN
is different. -->

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 4 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | GET /nnrf-disc/v1/nf-instances?target-plmn-list=001-01 (AMF→SCP, with discovery headers) |
| 5 | 127.0.0.1   | 127.0.1.250 | 7777 | SBI      | GET /nnrf-disc/... (SCP→Home SEPP)  |
| 6 | 127.0.0.1   | 127.0.2.252 | 7777 | SBI      | GET /nnrf-disc/... (Home SEPP→Visiting SEPP N32) |
| 7 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | GET /nnrf-disc/... (Visiting SEPP→Visiting SCP) |
| 8 | 127.0.0.1   | 127.0.2.10  |  80  | SBI      | GET /nnrf-disc/... (Visiting SCP→Visiting NRF) |

**What to verify**: The NRF discovery traverses SEPP (Home SCP → Home SEPP
→ Visiting SEPP → Visiting SCP → Visiting NRF). The query includes
`target-plmn-list` with MCC=001, MNC=01.

#### Step 2d: CreateUEContext (5-hop SEPP chain)

<!-- **This is the most important message to verify for SEPP routing.** -->

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 9 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST /namf-comm/v1/ue-contexts/{imsi} (Home AMF→Home SCP) |
|   |             |             |      |          | *(SCP detects target FQDN is in VPLMN, routes to SEPP)* |
|10 | 127.0.0.1   | 127.0.1.250 | 7777 | SBI      | POST /namf-comm/v1/ue-contexts/{imsi} (Home SCP→Home SEPP) |
|11 | 127.0.0.1   | 127.0.2.252 | 7777 | SBI      | POST /namf-comm/v1/ue-contexts/{imsi} (Home SEPP→Visiting SEPP N32) |
|12 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | POST /namf-comm/v1/ue-contexts/{imsi} (Visiting SEPP→Visiting SCP) |
|13 | 127.0.0.1   | 127.0.2.5   |  80  | SBI      | POST /namf-comm/v1/ue-contexts/{imsi} (Visiting SCP→Visiting AMF) |

**What to verify**:
- All 5 hops appear with the **same URI path** `/namf-comm/v1/ue-contexts/{imsi}`
- The HTTP method is **POST** for all 5 hops
- The destination IPs are: `127.0.1.200` → `127.0.1.250` → `127.0.2.252` → `127.0.2.200` → `127.0.2.5`
- The message does **NOT** go directly from `127.0.0.1` to `127.0.2.5`
  (that would mean SEPP is bypassed)
- Source IP is `127.0.0.1` for all 5 hops (TCP outgoing connections)

**Note**: There may be a gap between hop 1 (frame ~390) and hops 2-5
(frames ~454-457) because the NRF discovery (step 2c) happens between them.

#### Step 2e: HandoverRequest / HandoverRequestAck

<!-- The Visiting AMF receives CreateUEContext and sends HandoverRequest to the
target gNB via NGAP: -->

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
|14 | 127.0.2.5   | 127.0.0.3   | SCTP | NGAP 13  | **HandoverRequest** (Visiting AMF → tgt gNB) |
|15 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 13  | **HandoverRequestAck** (tgt gNB → Visiting AMF) |

**What to verify**:
- HandoverRequest src is `127.0.2.5` (Visiting AMF), dst is `127.0.0.3` (target gNB)
- Contains UEAggregateMaximumBitRate IE
- Contains SecurityContext with non-zero NCC
- **LBO**: PDUSessionResourceSetupListHOReq is empty (no sessions to transfer)
- **HR**: PDUSessionResourceSetupListHOReq contains transferred sessions with
  PDUSessionResourceSetupRequestTransfer from V-SMF (UPF tunnel info, QoS flows)
- HandoverRequestAck TargetToSource-TransparentContainer should NOT show
  "Malformed Packet"
- **HR**: HandoverRequestAck PDUSessionResourceAdmittedList contains per-session
  HandoverRequestAcknowledgeTransfer (DL forwarding tunnel info)

#### Step 2f: CreateUEContext 201 Response (reverse through SEPP)

<!-- The HTTP/2 201 Created response travels back on the same TCP connections: -->

| # | Src         | Dst         |  | Description                            |
|---|-------------|-------------|--|----------------------------------------|
|16 | 127.0.2.5   | 127.0.0.1   |  | Visiting AMF → (back to Visiting SCP)  |
|17 | 127.0.2.200 | 127.0.0.1   |  | Visiting SCP → (back to Visiting SEPP) |
|18 | 127.0.2.252 | 127.0.0.1   |  | Visiting SEPP → (back to Home SEPP)    |
|19 | 127.0.1.250 | 127.0.0.1   |  | Home SEPP → (back to Home SCP)         |
|20 | 127.0.1.200 | 127.0.0.1   |  | Home SCP → (back to Home AMF)          |

**Note**: Not all response hops may be visible as distinct HTTP/2 frames in
tshark due to TCP segment combining. The key ones to look for are status `201`
from `127.0.2.5` (the Visiting AMF originated the response).

#### Step 2g: HandoverCommand

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
|21 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 12  | **HandoverCommand** (Home AMF → src gNB) |

**What to verify**: This is the SuccessfulOutcome for HandoverRequired
(same procedure code 12). Contains NASSecurityParametersFromNGRAN with NCC.
Contains TargetToSource-TransparentContainer (passed through from target gNB).

### Phase 3: Handover Execution

#### Step 3a: HandoverNotify

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
|22 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 11  | **HandoverNotify** (tgt gNB → Visiting AMF) |

**What to verify**: Src is `127.0.0.3` (target gNB), dst is `127.0.2.5`
(Visiting AMF). This signals the UE has arrived at the target cell.

#### Step 3b: N2InfoNotify (5-hop SEPP chain, reverse direction)

<!-- The Visiting AMF notifies the Home AMF that the handover is complete. This
goes through SEPP in the **opposite** direction from CreateUEContext. -->

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
|23 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | POST .../n2-info-notify (Visiting AMF→Visiting SCP) |
|24 | 127.0.0.1   | 127.0.2.250 | 7777 | SBI      | POST .../n2-info-notify (Visiting SCP→Visiting SEPP) |
|25 | 127.0.0.1   | 127.0.1.252 | 7777 | SBI      | POST .../n2-info-notify (Visiting SEPP→Home SEPP N32) |
|26 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../n2-info-notify (Home SEPP→Home SCP) |
|27 | 127.0.0.1   | 127.0.1.5   |  80  | SBI      | POST .../n2-info-notify (Home SCP→Home AMF) |

**What to verify**:
- All 5 hops visible with path containing `n2-info-notify`
- Destination IPs: `127.0.2.200` → `127.0.2.250` → `127.0.1.252` → `127.0.1.200` → `127.0.1.5`
- The message does **NOT** go directly to `127.0.1.5`
- Note the SEPP N32 direction is reversed: `127.0.1.252` (Home N32) receives
  from Visiting SEPP, whereas CreateUEContext used `127.0.2.252` (Visiting N32)
  receiving from Home SEPP

### Phase 4: Cleanup

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
|28 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../sm-contexts/{id}/release (AMF→SCP) |
|29 | 127.0.0.1   | 127.0.1.4   |  80  | SBI      | POST .../sm-contexts/{id}/release (SCP→SMF) |
|30 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 41  | **UEContextReleaseCommand** (Home AMF → src gNB) |
|31 | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 41  | **UEContextReleaseComplete** (src gNB → Home AMF) |
|32 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 42  | **UEContextReleaseRequest** (tgt gNB → Visiting AMF) |
|33 | 127.0.2.5   | 127.0.0.3   | SCTP | NGAP 41  | **UEContextReleaseCommand** (Visiting AMF → tgt gNB) |
|34 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 41  | **UEContextReleaseComplete** (tgt gNB → Visiting AMF) |

**What to verify**:
- PDU session release (`sm-contexts/{id}/release`) appears AFTER N2InfoNotify
- Source gNB context released by Home AMF (code 41 between 127.0.1.5 ↔ 127.0.0.2)
- Target gNB context released by Visiting AMF (code 42/41 between 127.0.2.5 ↔ 127.0.0.3)

---

## Summary Checklist

For a successful inter-PLMN N2 handover, verify ALL of the following:

### Common (LBO and HR)
- [ ] **Distinct gNB IPs**: Source gNB uses `127.0.0.2`, target gNB uses
      `127.0.0.3` in NGAP messages (not both `127.0.0.1`)
- [ ] **No Malformed Packets**: Transparent containers in HandoverRequired
      (code 12) and HandoverRequestAck (code 13) decode cleanly
- [ ] **CreateUEContext through SEPP (5 hops)**: POST `/namf-comm/v1/ue-contexts/{imsi}`
      hits dst IPs in order: `127.0.1.200` → `127.0.1.250` → `127.0.2.252` → `127.0.2.200` → `127.0.2.5`
- [ ] **N2InfoNotify through SEPP (5 hops)**: POST `.../n2-info-notify`
      hits dst IPs in order: `127.0.2.200` → `127.0.2.250` → `127.0.1.252` → `127.0.1.200` → `127.0.1.5`
- [ ] **NRF Discovery through SEPP**: GET `/nnrf-disc/v1/nf-instances` with
      target-plmn-list containing 001-01 routed through SEPP
- [ ] **No direct AMF-to-AMF traffic**: No SBI message goes directly to
      `127.0.2.5` or `127.0.1.5` without passing through SCP/SEPP
- [ ] **HandoverRequest to target gNB**: NGAP 13 from `127.0.2.5` → `127.0.0.3`
- [ ] **HandoverNotify from target gNB**: NGAP 11 from `127.0.0.3` → `127.0.2.5`
- [ ] **UE AMBR present**: HandoverRequest (code 13) contains
      UEAggregateMaximumBitRate
- [ ] **NCC present**: HandoverRequest SecurityContext contains a non-zero NCC

### LBO-Specific
- [ ] **No PDU sessions in HandoverRequest**: PDUSessionResourceSetupListHOReq empty
- [ ] **PDU session modify before handover**: `sm-contexts/{id}/modify` appears
      after HandoverRequired
- [ ] **PDU session release after handover**: `sm-contexts/{id}/release` appears
      after N2InfoNotify
- [ ] **No V-SMF insertion**: No CreateSMContext to V-SMF (`127.0.2.4`) or
      PFCP traffic to V-UPF (`127.0.2.7`) during handover preparation
- [ ] **New PDU session at V-AMF**: POST `/nsmf-pdusession/v1/sm-contexts` to
      visiting SMF after handover completes (new session, not transferred)
- [ ] **Post-HO GTP-U via V-UPF**: GTP-U T-PDU goes through V-UPF
      (`127.0.2.7`) in new session (no N9 tunnel to H-UPF)

### HR-Specific (V-SMF Insertion)
- [ ] **V-SMF CreateSMContext**: POST `/nsmf-pdusession/v1/sm-contexts` to
      V-SMF (`127.0.2.4`) with `hoState: PREPARING` after CreateUEContext arrives
- [ ] **V-SMF → H-SMF Create through SEPP**: POST `/nsmf-pdusession/v1/pdu-sessions`
      with `ho_preparation_indication` routed through SCP→SEPP to H-SMF (`127.0.1.4`)
- [ ] **V-UPF N4 Session Establishment**: PFCP Session Establishment on V-UPF
      (`127.0.2.7`) before HandoverRequest
- [ ] **PDU sessions in HandoverRequest**: PDUSessionResourceSetupListHOReq
      contains V-UPF N3 info from V-SMF CreateSMContext response
- [ ] **V-SMF UpdateSMContext PREPARED**: `sm-contexts/{id}/modify` with
      `n2SmInfoType: HANDOVER_REQ_ACK` to V-SMF after HandoverRequestAck
- [ ] **HandoverCommand after V-SMF**: HandoverCommand (NGAP 12) appears only
      after V-SMF returns HANDOVER_CMD (carried in CreateUEContext 201 response)
- [ ] **RANStatusTransfer forwarded**: NGAP 47 (Uplink) → N2InfoNotify through
      SEPP → NGAP 48 (Downlink) between source and target gNBs
- [ ] **V-SMF UpdateSMContext COMPLETED**: `sm-contexts/{id}/modify` with
      `hoState: COMPLETED` to V-SMF after HandoverNotify
- [ ] **V-UPF N4 path switch**: PFCP Session Modification on V-UPF (`127.0.2.7`)
      for DL data path switch and UL FAR after COMPLETED
- [ ] **V-SMF → H-SMF HsmfUpdateData**: PATCH `/nsmf-pdusession/v1/pdu-sessions/{id}`
      through SEPP to H-SMF (`127.0.1.4`) with DL CN tunnel info (V-UPF N3 addr)
- [ ] **PSA-UPF N4 path switch**: PFCP Session Modification on PSA-UPF
      (`127.0.1.7`) to update DL FAR to V-UPF N3 address
- [ ] **Post-HO GTP-U via V-UPF**: GTP-U T-PDU goes gNB → V-UPF → PSA-UPF
      (not directly gNB → H-UPF)

---

## Home-Routed (HR) Handover — V-SMF Insertion Message Flows

The HR handover path uses **V-SMF insertion** per TS 23.502 §4.23.7.3. Unlike
LBO where the source AMF contacts the SMF, in HR the **target AMF** creates a
V-SMF session in the visited PLMN. The V-SMF then contacts the H-SMF in the
home PLMN through SEPP.

### HR Preparation Phase: V-SMF Insertion

After HandoverRequired (NGAP 12), the source (Home) AMF sends `CreateUEContext`
to the target (Visiting) AMF. The target AMF selects a V-SMF and initiates
the V-SMF insertion:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 12  | HandoverRequired (src gNB → Home AMF) |
| 2 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST /namf-comm/v1/ue-contexts/{imsi} (CreateUEContext Home AMF→SCP) |
|   |             |             |      |          | *(5-hop SEPP chain to Visiting AMF, see Phase 2d above)* |
| 3 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | POST /nsmf-pdusession/v1/sm-contexts (T-AMF→SCP→V-SMF CreateSMContext PREPARING) |
| 4 | 127.0.0.1   | 127.0.2.4   |  80  | SBI      | POST /nsmf-pdusession/v1/sm-contexts (SCP→V-SMF) |
|   |             |             |      |          | *V-SMF creates V-UPF N4 session, then contacts H-SMF:* |
| 5 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | POST /nsmf-pdusession/v1/pdu-sessions (V-SMF→SCP, HO Create to H-SMF) |
|   |             |             |      |          | *(5-hop SEPP chain from Visiting PLMN → Home PLMN:* |
|   |             |             |      |          | *V-SMF→SCP2→SEPP2→SEPP1→SCP1→H-SMF)* |
| 6 | 127.0.0.1   | 127.0.1.4   |  80  | SBI      | POST /nsmf-pdusession/v1/pdu-sessions (SCP→H-SMF, ho_preparation_indication) |
|   |             |             |      |          | *H-SMF stores V-SMF reference, returns 201 with session context* |
|   |             |             |      |          | *V-SMF sends deferred 201 CREATED to T-AMF with N2 SM (V-UPF N3 info)* |
| 7 | 127.0.2.5   | 127.0.0.3   | SCTP | NGAP 13  | **HandoverRequest** (T-AMF → target gNB, with V-UPF tunnel) |

**What to verify (HR V-SMF insertion)**:
- `CreateUEContext` goes through SEPP (5 hops) before V-SMF contact
- V-SMF CreateSMContext: POST `/nsmf-pdusession/v1/sm-contexts` to `127.0.2.4`
- V-SMF → H-SMF Create: POST `/nsmf-pdusession/v1/pdu-sessions` through SEPP to `127.0.1.4`
- HandoverRequest contains PDUSessionResourceSetupListHOReq with V-UPF N3 info
- V-UPF N4 PFCP traffic visible on `127.0.2.7` (V-UPF address)

### HR PREPARED Phase: HandoverRequestAck + Command

After target gNB sends HandoverRequestAck, the target AMF sends
`UpdateSMContext(hoState=PREPARED)` to V-SMF with the ack transfer. V-SMF
returns HandoverCommandTransfer. Target AMF responds to CreateUEContext 201,
and source AMF sends HandoverCommand:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 13  | HandoverRequestAck (target gNB → T-AMF) |
| 2 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | POST .../sm-contexts/{id}/modify hoState=PREPARED (T-AMF→SCP) |
| 3 | 127.0.0.1   | 127.0.2.4   |  80  | SBI      | POST .../sm-contexts/{id}/modify (SCP→V-SMF) |
|   |             |             |      |          | *V-SMF returns HANDOVER_CMD transfer* |
|   |             |             |      |          | *CreateUEContext 201 response back through SEPP (5 hops)* |
| 4 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 12  | **HandoverCommand** (Home AMF → src gNB) |

**What to verify (HR PREPARED)**:
- `sm-contexts/{id}/modify` with `n2SmInfoType: HANDOVER_REQ_ACK` to V-SMF
- V-SMF response includes `n2SmInfoType: HANDOVER_CMD` transfer
- `CreateUEContext 201` includes per-session HandoverCommandTransfer
- HandoverCommand (NGAP 12 successfulOutcome) appears AFTER V-SMF responds

### HR RANStatusTransfer Phase

After HandoverCommand, the source gNB sends UplinkRANStatusTransfer. The
source AMF forwards it via N2InfoNotify through SEPP to the target AMF, which
delivers DownlinkRANStatusTransfer to the target gNB:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 47  | UplinkRANStatusTransfer (src gNB → Home AMF) |
| 2 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../n2-info-notify (RAN_STATUS, Home AMF→SCP) |
|   |             |             |      |          | *(5-hop SEPP chain to Visiting AMF)* |
| 3 | 127.0.2.5   | 127.0.0.3   | SCTP | NGAP 48  | DownlinkRANStatusTransfer (T-AMF → target gNB) |

**What to verify (RANStatusTransfer)**:
- NGAP 47 from `127.0.0.2` → `127.0.1.5` (source gNB → Home AMF)
- N2InfoNotify with RAN status data through SEPP (5 hops)
- NGAP 48 from `127.0.2.5` → `127.0.0.3` (Visiting AMF → target gNB)

### HR Completion Phase: V-SMF COMPLETED + Data Path Switch

After HandoverNotify from target gNB, the target AMF sends
`UpdateSMContext(hoState=COMPLETED)` to V-SMF. V-SMF modifies V-UPF N4 to
switch the data path. Target AMF also sends N2InfoNotify to source AMF:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 11  | **HandoverNotify** (target gNB → T-AMF) |
| 2 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | POST .../sm-contexts/{id}/modify hoState=COMPLETED (T-AMF→SCP→V-SMF) |
|   |             |             |      |          | *V-SMF modifies V-UPF N4 (UL FAR + DL path switch):* |
| 3 | 127.0.0.1   | 127.0.2.7   | 8805 | PFCP     | PFCP Session Modification Request (V-SMF→V-UPF) |
| 4 | 127.0.2.7   | 127.0.0.1   | 8805 | PFCP     | PFCP Session Modification Response (V-UPF→V-SMF) |
|   |             |             |      |          | *V-SMF sends HsmfUpdateData to H-SMF via SEPP (DL CN tunnel update):* |
| 5 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | PATCH /nsmf-pdusession/v1/pdu-sessions/{id} (V-SMF→SCP, HsmfUpdateData) |
|   |             |             |      |          | *(5-hop SEPP chain: V-SMF→SCP2→SEPP2→SEPP1→SCP1→H-SMF)* |
| 6 | 127.0.0.1   | 127.0.1.4   |  80  | SBI      | PATCH /nsmf-pdusession/v1/pdu-sessions/{id} (SCP→H-SMF) |
|   |             |             |      |          | *H-SMF modifies PSA-UPF N4 (DL FAR → V-UPF N3 addr):* |
| 7 | 127.0.0.1   | 127.0.1.7   | 8805 | PFCP     | PFCP Session Modification Request (H-SMF→PSA-UPF) |
| 8 | 127.0.1.7   | 127.0.0.1   | 8805 | PFCP     | PFCP Session Modification Response (PSA-UPF→H-SMF) |
|   |             |             |      |          | *H-SMF returns 204 → V-SMF returns 200 to T-AMF* |
| 9 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | POST .../n2-info-notify (HANDOVER_COMPLETED, T-AMF→SCP→SEPP→Home AMF) |
|   |             |             |      |          | *(5-hop SEPP chain to Home AMF)* |
|10 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 41  | UEContextReleaseCommand (Home AMF → src gNB) |

**What to verify (HR COMPLETED)**:
- `sm-contexts/{id}/modify` with `hoState: COMPLETED` to V-SMF at `127.0.2.4`
- PFCP Session Modification on V-UPF (`127.0.2.7`) — UL FAR pushed, DL path switched
- HsmfUpdateData (PATCH) to H-SMF (`127.0.1.4`) through SEPP — DL CN tunnel update
- PFCP Session Modification on PSA-UPF (`127.0.1.7`) — DL FAR updated to V-UPF N3
- N2InfoNotify (HANDOVER_COMPLETED) through SEPP to Home AMF
- Source gNB released after notification

### HR Post-Handover GTP-U Data Path Verification

After handover completes, GTP-U data follows the path:
UE → target gNB → **V-UPF** (`127.0.2.7`) → **PSA-UPF** (`127.0.1.7`) → DN
(and reverse for DL). This confirms the V-SMF insertion and N4 path switch
worked correctly.

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.3   | 127.0.2.7   | GTP-U| GTP-U    | T-PDU UL (target gNB → V-UPF, TEID=V-UPF N3) |
| 2 | 127.0.2.7   | 127.0.1.7   | GTP-U| GTP-U    | T-PDU UL (V-UPF → PSA-UPF, TEID=H-UPF N9) |
| 3 | 127.0.1.7   | 127.0.2.7   | GTP-U| GTP-U    | T-PDU DL (PSA-UPF → V-UPF, TEID=V-UPF N9) |
| 4 | 127.0.2.7   | 127.0.0.3   | GTP-U| GTP-U    | T-PDU DL (V-UPF → target gNB, TEID=gNB N3) |

**What to verify (Post-HO GTP-U)**:
- UL GTP-U goes to V-UPF (`127.0.2.7`), NOT to H-UPF (`127.0.1.7`) directly
- V-UPF forwards to PSA-UPF via N9 tunnel
- DL GTP-U returns from PSA-UPF → V-UPF → target gNB
- No GTP-U to/from source gNB (`127.0.0.2`) after handover

### HR Cancel: V-SMF Rollback

When `HandoverCancel` arrives after `HandoverCommand`, the source (Home) AMF
sends `HandoverCancelAcknowledge` immediately, then sends
`UpdateSMContext(hoState=CANCELLED)` to H-SMF which clears V-SMF reference:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 12  | HandoverCancel (src gNB → Home AMF) |
| 2 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 12  | HandoverCancelAck (immediate) |
| 3 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../sm-contexts/{id}/modify hoState=CANCELLED (to H-SMF) |

**What to verify (HR Cancel)**:
- CANCELLED sent to H-SMF (`127.0.1.4`), not to V-SMF
- H-SMF clears V-SMF reference, reverts to non-roaming mode
- Target AMF's UE context cleaned up via visiting gNB UE context release

### HR Failure: V-SMF Release

When target gNB sends `HandoverFailure` (NGAP 13 unsuccessfulOutcome), the
target AMF releases V-SMF sessions and sends error on `CreateUEContext`.
Source AMF sends `HandoverPreparationFailure`:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 13  | HandoverFailure (tgt gNB → T-AMF) |
| 2 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | POST .../sm-contexts/{id}/release (T-AMF→V-SMF ReleaseSMContext) |
|   |             |             |      |          | *V-SMF releases V-UPF N4, notifies H-SMF to remove V-SMF reference* |
|   |             |             |      |          | *CreateUEContext 403 response back through SEPP* |
| 3 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 12  | HandoverPreparationFailure |

---

## Local-Breakout (LBO) Handover — Detailed Message Flow

In LBO mode, PDU sessions are anchored at the visiting PLMN's UPF. During
inter-PLMN N2 handover, the source AMF **does not** transfer PDU sessions
to the target AMF because the sessions are LBO (not home-routed). After
handover, the old sessions are released and new PDU sessions are established
at the visiting AMF.

### LBO Preparation Phase

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 12  | HandoverRequired (src gNB → Home AMF) |
| 2 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST /nsmf-pdusession/v1/sm-contexts/{id}/modify (S-AMF→SCP→SMF) |
|   |             |             |      |          | *No V-SMF insertion — LBO sessions excluded from CreateUEContext* |
| 3 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST /namf-comm/v1/ue-contexts/{imsi} (CreateUEContext, 5 SEPP hops) |
|   |             |             |      |          | *PDU session list empty — no sessions to transfer* |
| 4 | 127.0.2.5   | 127.0.0.3   | SCTP | NGAP 13  | HandoverRequest (T-AMF → tgt gNB, no PDU sessions) |
| 5 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 13  | HandoverRequestAck (tgt gNB → T-AMF) |
|   |             |             |      |          | *CreateUEContext 201 response back through SEPP (5 hops)* |
| 6 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 12  | HandoverCommand (Home AMF → src gNB) |

**What to verify (LBO Preparation)**:
- CreateUEContext has empty PDUSessionResourceSetupListHOReq
- No V-SMF CreateSMContext or PFCP traffic to `127.0.2.4` or `127.0.2.7`
- HandoverRequest (NGAP 13) has no PDU session resources

### LBO Execution Phase

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 11  | HandoverNotify (tgt gNB → T-AMF) |
| 2 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | POST .../n2-info-notify (HANDOVER_COMPLETED, T-AMF→SCP→SEPP→Home AMF) |
|   |             |             |      |          | *(5-hop SEPP chain to Home AMF)* |
| 3 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../sm-contexts/{id}/release (S-AMF→SCP→SMF, release old sessions) |
| 4 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 41  | UEContextReleaseCommand (Home AMF → src gNB) |

**What to verify (LBO Execution)**:
- N2InfoNotify goes through SEPP (5 hops) to Home AMF
- Old PDU sessions released at S-AMF **after** receiving N2InfoNotify
- Source gNB context released

### LBO Post-Handover: New PDU Session Establishment

After handover, the UE establishes **new** PDU sessions at the visiting AMF.
These are standard PDU session establishment procedures — no V-SMF insertion
since LBO sessions are anchored at the visiting PLMN.

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 46  | UL NAS: PDU Session Est Req (tgt gNB → V-AMF) |
| 2 | 127.0.0.1   | 127.0.2.200 | 7777 | SBI      | POST /nsmf-pdusession/v1/sm-contexts (V-AMF→SCP→SMF) |
|   |             |             |      |          | *SMF creates session, establishes V-UPF N4, calls N1N2MessageTransfer* |
| 3 | 127.0.2.5   | 127.0.0.3   | SCTP | NGAP 29  | PDUSessionResourceSetupRequest (V-AMF → tgt gNB) |
| 4 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 29  | PDUSessionResourceSetupResponse (tgt gNB → V-AMF) |

### LBO Post-Handover GTP-U Data Path Verification

After new PDU session establishment, GTP-U data flows directly through the
visiting PLMN's UPF:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.3   | 127.0.2.7   | GTP-U| GTP-U    | T-PDU UL (target gNB → V-UPF) |
| 2 | 127.0.2.7   | 127.0.0.3   | GTP-U| GTP-U    | T-PDU DL (V-UPF → target gNB) |

**What to verify (LBO Post-HO GTP-U)**:
- GTP-U goes to V-UPF (`127.0.2.7`), **not** to H-UPF (`127.0.1.7`)
- No N9 tunnel (V-UPF is the anchor, not a relay)
- No GTP-U to/from source gNB (`127.0.0.2`) after handover

---

## SEPP Direction Summary

```
CreateUEContext / NRF Discovery (Home → Visiting):
  Home SCP → Home SEPP(SBI) → Visiting SEPP(N32) → Visiting SCP
  127.0.1.200 → 127.0.1.250  → 127.0.2.252      → 127.0.2.200

N2InfoNotify (Visiting → Home):
  Visiting SCP → Visiting SEPP(SBI) → Home SEPP(N32) → Home SCP
  127.0.2.200  → 127.0.2.250        → 127.0.1.252    → 127.0.1.200

V-SMF → H-SMF (HR V-SMF insertion, Visiting → Home):
  V-SMF → Visiting SCP → Visiting SEPP(SBI) → Home SEPP(N32) → Home SCP → H-SMF
  127.0.2.4 → 127.0.2.200 → 127.0.2.250 → 127.0.1.252 → 127.0.1.200 → 127.0.1.4
```

Note: Each PLMN's SEPP has two interfaces:
- **SBI interface** (receives from local SCP): Home=127.0.1.250, Visiting=127.0.2.250
- **N32 interface** (receives from peer SEPP): Home=127.0.1.251/252, Visiting=127.0.2.251/252

---

## Test-Specific Variations

### LBO Test Suite (n2-handover-lbo)

#### LBO Test 1: Direct Forwarding Cross-PLMN
Standard flow as described above. One PDU session established, released after
handover.

#### LBO Test 2: Indirect Forwarding (Different TAC)
Same handover flow but target gNB has a different TAC (23 vs 22). The NGAP
and SBI flow is identical.

#### LBO Test 3: Multiple PDU Sessions
Same handover flow but with active PDU sessions. Multiple
`sm-contexts/{id}/modify` calls before handover and multiple
`sm-contexts/{id}/release` calls after.

#### LBO Test 4: Handover Cancel
Handover starts normally through HandoverCommand, then source gNB cancels:
- All of Phase 2 (steps 2a–2g) occurs normally
- **Instead of Phase 3**: source gNB sends HandoverCancel
  - NGAP 12: `127.0.0.2 → 127.0.1.5` (new initiating message, not a response)
- **No HandoverNotify** (NGAP 11) from target gNB
- **No N2InfoNotify** through SEPP
- Source AMF sends UEContextReleaseCommand to source gNB as normal cleanup

#### LBO Test 5: Handover Failure
Target gNB rejects HandoverRequest:
- Steps 2a–2d occur normally (HandoverRequired, modify, NRF discovery, CreateUEContext)
- **HandoverFailure**: NGAP 13 `127.0.0.3 → 127.0.2.5` (unsuccessfulOutcome)
- CreateUEContext error response back through SEPP (5-hop reverse)
- **HandoverPreparationFailure**: NGAP 12 `127.0.1.5 → 127.0.0.2` (unsuccessfulOutcome)
- **No HandoverCommand**, no HandoverNotify, no N2InfoNotify

### HR Test Suite (n2-handover-hr)

#### HR Test 1: Basic Home-Routed Handover (Single PDU Session)
Full HR V-SMF insertion flow: HandoverRequired → CreateUEContext through SEPP →
T-AMF selects V-SMF → V-SMF CreateSMContext(PREPARING) → V-SMF contacts H-SMF
through SEPP → HandoverRequest with V-UPF N3 → HandoverRequestAck →
UpdateSMContext(PREPARED) → CreateUEContext 201 → HandoverCommand →
RANStatusTransfer → HandoverNotify → UpdateSMContext(COMPLETED) → V-UPF path
switch → N2InfoNotify → source release. Single `internet` session (PSI 5).

#### HR Test 2: Indirect Forwarding Home-Routed Handover
Same as HR Test 1 but with indirect forwarding (target gNB reports
`data_forwarding_not_possible`). V-SMF may set up indirect forwarding tunnels
via V-UPF N4 before returning HANDOVER_CMD.

#### HR Test 3: Multiple PDU Sessions Home-Routed
Two HR sessions (`internet` PSI 5, `ims` PSI 6). T-AMF creates two V-SMF
sessions — `CreateUEContext` includes both sessions, HandoverCommand waits
for all V-SMF HANDOVER_CMD responses. Two sets of V-SMF→H-SMF SEPP hops.

#### HR Test 4: Handover Cancel with HR Rollback
Full HR preparation through HandoverCommand, then source gNB cancels:
- V-SMF insertion completes normally (V-SMF created, H-SMF notified)
- Source gNB sends HandoverCancel (NGAP 12 initiatingMessage)
- Source (Home) AMF sends HandoverCancelAcknowledge immediately
- Source AMF sends `UpdateSMContext(hoState=CANCELLED)` to H-SMF
- H-SMF clears V-SMF reference, reverts to non-roaming mode
- Target AMF's UE context cleaned up through visiting gNB release

#### HR Test 5: Handover Failure with HR Rollback
Target gNB rejects HandoverRequest after V-SMF insertion started:
- V-SMF insertion begins (CreateSMContext PREPARING, V-SMF→H-SMF Create)
- CreateUEContext sent through SEPP to Visiting AMF
- Target gNB sends HandoverFailure → T-AMF releases V-SMF sessions
- T-AMF sends ReleaseSMContext to V-SMF, V-SMF cleans up V-UPF N4
- CreateUEContext 403 response back through SEPP
- Source AMF sends HandoverPreparationFailure to source gNB
- UE remains registered on Home AMF with original sessions
