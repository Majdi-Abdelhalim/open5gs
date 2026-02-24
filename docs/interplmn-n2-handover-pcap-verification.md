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

This single filter shows all handover-relevant messages (NGAP + key SBI) in
chronological order, excluding NRF discovery, UDR, UDM, PCF, BSF, and AUSF
background traffic:

```bash
tshark -r handover_test.pcap \
    -d tcp.port==80,http2 -d tcp.port==7777,http2 \
    -Y 'ngap || (http2.headers.path and (http2.headers.path contains "namf-comm" or http2.headers.path contains "nsmf-pdusession"))' \
    -T fields -e frame.number -e ip.src -e ip.dst -e tcp.dstport \
    -e ngap.procedureCode -e http2.headers.method -e http2.headers.path
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

### HR-Specific
- [ ] **PDU sessions in HandoverRequest**: PDUSessionResourceSetupListHOReq
      contains transferred sessions with N2 SM Info from V-SMF
- [ ] **V-SMF HANDOVER_REQUIRED**: `sm-contexts/{id}/modify` with
      `hoState: PREPARING` appears before CreateUEContext
- [ ] **V-SMF HANDOVER_REQ_ACK**: `sm-contexts/{id}/modify` with
      `n2SmInfoType: HANDOVER_REQ_ACK` appears after CreateUEContext 201
- [ ] **HandoverCommand delayed**: HandoverCommand (NGAP 12) appears only
      after V-SMF returns HANDOVER_CMD (not immediately after CreateUEContext)
- [ ] **V-SMF COMPLETED**: `sm-contexts/{id}/modify` with
      `hoState: COMPLETED` appears after N2InfoNotify
- [ ] **Session release after COMPLETED**: `sm-contexts/{id}/release` appears
      after V-SMF COMPLETED response

---

## Home-Routed (HR) Handover — Additional Message Flows

The HR handover path includes additional V-SMF interactions not present in LBO.
These are the key differences visible in pcap captures.

### HR Preparation Phase: V-SMF Interactions

After HandoverRequired (NGAP 12), the Home AMF sends `UpdateSMContext` to the
V-SMF for each HR session before sending `CreateUEContext`:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 12  | HandoverRequired (src gNB → Home AMF) |
| 2 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../sm-contexts/{id}/modify hoState=PREPARING (AMF→SCP) |
| 3 | 127.0.0.1   | 127.0.1.4   |  80  | SBI      | POST .../sm-contexts/{id}/modify (SCP→V-SMF) |
|   |             |             |      |          | *V-SMF returns N2 SM Info (PDUSessionResourceSetupRequestTransfer)* |
| 4 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST /namf-comm/v1/ue-contexts/{imsi} (CreateUEContext with PDU sessions) |

**What to verify (HR)**:
- `sm-contexts/{id}/modify` appears BEFORE `CreateUEContext`
- The modify request includes `hoState: PREPARING` and `n2SmInfoType: HANDOVER_REQ`
- V-SMF response includes N2 SM binary data (PDUSessionResourceSetupRequestTransfer)
- `CreateUEContext` request body includes `pduSessionList` with N2SmInformation entries

### HR Handover Completion: V-SMF Ack and Command

After `CreateUEContext` 201 response returns with per-session ack transfers, the
Home AMF sends `UpdateSMContext(hoState=PREPARED)` for each HR session:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../sm-contexts/{id}/modify hoState=PREPARED (AMF→SCP) |
| 2 | 127.0.0.1   | 127.0.1.4   |  80  | SBI      | POST .../sm-contexts/{id}/modify (SCP→V-SMF) |
|   |             |             |      |          | *V-SMF returns HANDOVER_CMD transfer* |
| 3 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 12  | HandoverCommand (Home AMF → src gNB) |

**What to verify (HR)**:
- `sm-contexts/{id}/modify` with `n2SmInfoType: HANDOVER_REQ_ACK` appears
  AFTER `CreateUEContext` 201 response
- V-SMF response includes `n2SmInfoType: HANDOVER_CMD` with binary transfer data
- `HandoverCommand` (NGAP 12 successfulOutcome) is sent AFTER V-SMF responds
  (not immediately after CreateUEContext 201 like in LBO)

### HR Post-Handover: V-SMF Completion

After `N2InfoNotify(HANDOVER_COMPLETED)`, the Home AMF sends
`UpdateSMContext(hoState=COMPLETED)` and then releases the HR session:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../sm-contexts/{id}/modify hoState=COMPLETED (AMF→SCP) |
| 2 | 127.0.0.1   | 127.0.1.4   |  80  | SBI      | POST .../sm-contexts/{id}/modify (SCP→V-SMF) |
| 3 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../sm-contexts/{id}/release (AMF→SCP) |
| 4 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 41  | UEContextReleaseCommand (Home AMF → src gNB) |

**What to verify (HR)**:
- `sm-contexts/{id}/modify` with `hoState: COMPLETED` appears AFTER `N2InfoNotify`
- Session release (`sm-contexts/{id}/release`) appears AFTER the COMPLETED response
- UEContextReleaseCommand appears on the source gNB

### HR Cancel: V-SMF Rollback

When `HandoverCancel` arrives after `HandoverCommand`, the Home AMF sends
`HandoverCancelAcknowledge` immediately, then `UpdateSMContext(hoState=CANCELLED)`
to the V-SMF:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.2   | 127.0.1.5   | SCTP | NGAP 12  | HandoverCancel (src gNB → Home AMF) |
| 2 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 12  | HandoverCancelAck (immediate) |
| 3 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../sm-contexts/{id}/modify hoState=CANCELLED |

### HR Failure: V-SMF Rollback

When target gNB sends `HandoverFailure` (NGAP 13 unsuccessfulOutcome), the
Visiting AMF responds with error on `CreateUEContext`. The Home AMF sends
`HandoverPreparationFailure` and then `UpdateSMContext(hoState=CANCELLED)`:

| # | Src         | Dst         | Port | Protocol | Message                       |
|---|-------------|-------------|------|----------|-------------------------------|
| 1 | 127.0.0.3   | 127.0.2.5   | SCTP | NGAP 13  | HandoverFailure (tgt gNB → Visiting AMF) |
|   |             |             |      |          | *CreateUEContext 403 response back through SEPP* |
| 2 | 127.0.1.5   | 127.0.0.2   | SCTP | NGAP 12  | HandoverPreparationFailure |
| 3 | 127.0.0.1   | 127.0.1.200 | 7777 | SBI      | POST .../sm-contexts/{id}/modify hoState=CANCELLED |

---

## SEPP Direction Summary

```
CreateUEContext / NRF Discovery (Home → Visiting):
  Home SCP → Home SEPP(SBI) → Visiting SEPP(N32) → Visiting SCP
  127.0.1.200 → 127.0.1.250  → 127.0.2.252      → 127.0.2.200

N2InfoNotify (Visiting → Home):
  Visiting SCP → Visiting SEPP(SBI) → Home SEPP(N32) → Home SCP
  127.0.2.200  → 127.0.2.250        → 127.0.1.252    → 127.0.1.200
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
Full HR flow: HANDOVER_REQUIRED → CreateUEContext (with PDU sessions) →
HandoverRequestAck (with admitted sessions) → HANDOVER_REQ_ACK → HANDOVER_CMD →
HandoverCommand → HandoverNotify → N2InfoNotify → COMPLETED → release.
Single `internet` session (PSI 5).

#### HR Test 2: Indirect Forwarding Home-Routed Handover
Same as HR Test 1 but with indirect forwarding (target gNB reports
`data_forwarding_not_possible`). V-SMF may set up indirect forwarding tunnels
via PFCP before returning HANDOVER_CMD.

#### HR Test 3: Multiple PDU Sessions Home-Routed
Two HR sessions (`internet` PSI 5, `ims` PSI 6). Multiple V-SMF interactions
in parallel — `CreateUEContext` includes both sessions, HandoverCommand waits
for all V-SMF HANDOVER_CMD responses.

#### HR Test 4: Handover Cancel with HR Rollback
Full HR preparation through HandoverCommand, then source gNB cancels:
- V-SMF interactions for HANDOVER_REQUIRED and HANDOVER_REQ_ACK complete normally
- Source gNB sends HandoverCancel (NGAP 12 initiatingMessage)
- Home AMF sends HandoverCancelAcknowledge immediately
- Home AMF sends `UpdateSMContext(hoState=CANCELLED)` to V-SMF (async rollback)
- V-SMF clears prepared handover state

#### HR Test 5: Handover Failure with HR Rollback
Target gNB rejects HandoverRequest after HR preparation started:
- V-SMF interactions for HANDOVER_REQUIRED complete normally
- CreateUEContext sent with PDU sessions to Visiting AMF
- Target gNB sends HandoverFailure → Visiting AMF returns 403
- Home AMF sends HandoverPreparationFailure to source gNB
- Home AMF sends `UpdateSMContext(hoState=CANCELLED)` to V-SMF (async rollback)
- UE remains registered on Home AMF with original sessions
