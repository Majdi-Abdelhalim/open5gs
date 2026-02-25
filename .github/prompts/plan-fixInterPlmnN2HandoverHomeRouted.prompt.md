## Plan: Fix Inter-PLMN N2 Handover for Home-Routed Roaming (V-SMF Insertion per TS 23.502 §4.9.1.3 + §4.23.7)

**TL;DR**: The current HR handover is fundamentally broken — the source AMF (H-AMF) incorrectly contacts the H-SMF before CreateUEContext, and no V-SMF is ever inserted at the target PLMN. Per TS 23.502 §4.23.7.3, the correct flow for V-SMF insertion is: Source AMF sends CreateUEContext directly (no prior SMF contact), then the Target AMF (V-AMF) selects a V-SMF in the visited PLMN, sends `CreateSMContext(hoState=PREPARING)`, which triggers V-SMF→H-SMF context retrieval + V-UPF allocation + path registration. This requires significant changes across AMF, SMF, and test code. RANStatusTransfer forwarding is added via N2InfoNotify to achieve seamless handover.

**Network Topology for V-SMF Insertion:**

| Role | NF | PLMN | IP | Notes |
|------|----|------|----|-------|
| S-AMF / H-AMF | AMF | 999-70 | 127.0.1.5 | Source, UE's home |
| T-AMF / V-AMF | AMF | 001-01 | 127.0.2.5 | Target, visited |
| H-SMF | SMF | 999-70 | 127.0.1.4 | Initially regular SMF, becomes H-SMF |
| V-SMF (inserted) | SMF | 001-01 | 127.0.2.4 | Inserted during handover |
| PSA UPF | UPF | 999-70 | 127.0.1.7 | PDU Session Anchor |
| V-UPF (inserted) | UPF | 001-01 | 127.0.2.7 | Visited UPF, inserted during HO |

Post-handover data path: **UE → T-gNB → N3 → V-UPF (001-01) → N9 → PSA UPF (999-70) → DN**

**Steps**

---

### Phase 1: Rewrite Test Expected Message Flow

Rewrite [tests/roaming/n2-handover-hr-test.c](tests/roaming/n2-handover-hr-test.c) test functions to expect the correct 3GPP §4.23.7.3 V-SMF insertion sequence. This is test-only; implementations will be fixed in subsequent phases. Tests will FAIL until implementation catches up.

**Current (broken) test flow for test1:**
1. HandoverRequired → S-AMF
2. *(S-AMF → UpdateSMContext(HO_REQUIRED) → SMF)* — **WRONG: no SMF should be contacted**
3. *(S-AMF → CreateUEContext with SMF's N2 SM)* — **WRONG: N2 SM should come from V-SMF**
4. HandoverRequest ← T-AMF (with N2 SM from H-SMF) — **WRONG origin**
5. HandoverRequestAck → T-AMF
6. *(T-AMF → 201 Response)* — **WRONG: should go through V-SMF first**
7. *(S-AMF → UpdateSMContext(HO_REQ_ACK))* — **WRONG: S-AMF shouldn't contact SMF**
8. HandoverCommand ← S-AMF
9. HandoverNotify → T-AMF
10. UEContextReleaseCommand ← S-AMF

**Correct test flow (per §4.23.7.3):**
1. HandoverRequired → S-AMF (source gNB, with target PLMN 001-01)
2. *(server: S-AMF → CreateUEContext → T-AMF via SEPP, no SMF contact)*
3. *(server: T-AMF → NRF: discover V-SMF in 001-01)*
4. *(server: T-AMF → V-SMF: CreateSMContext(PREPARING, h_smf_uri, sm_context_ref))*
5. *(server: V-SMF → H-SMF: Nsmf_PDUSession_Create(ho_preparation_indication))*
6. *(server: V-SMF: select V-UPF, N4 Session Establishment to V-UPF)*
7. *(server: V-SMF → T-AMF: CreateSMContext Response with V-UPF N3 F-TEID)*
8. **HandoverRequest ← T-AMF** (on target gNB, with V-UPF's N3 tunnel in PDUSessionResourceSetupListHOReq)
9. **HandoverRequestAck → T-AMF** (from target gNB, with target gNB's N3 tunnel)
10. *(server: T-AMF → V-SMF: UpdateSMContext(PREPARED, HO Req Ack transfer))*
11. *(server: V-SMF → H-SMF: UpdateSMContext, forwarding tunnel setup)*
12. *(server: T-AMF → S-AMF: CreateUEContext 201 Response via SEPP)*
13. **HandoverCommand ← S-AMF** (on source gNB)
14. **UplinkRANStatusTransfer → S-AMF** (from source gNB) — **NEW**
15. *(server: S-AMF → T-AMF: N2InfoNotify(RAN_STATUS_TRANSFER) via SEPP)*
16. **DownlinkRANStatusTransfer ← T-AMF** (on target gNB) — **NEW**
17. **HandoverNotify → T-AMF** (from target gNB)
18. *(server: T-AMF → S-AMF: N2InfoNotify(HANDOVER_COMPLETED) via SEPP)*
19. *(server: T-AMF → V-SMF: UpdateSMContext(COMPLETED))*
20. *(server: V-SMF → V-UPF: N4 Modification, switch DL to target gNB)*
21. *(server: V-SMF → H-SMF: Nsmf_PDUSession_Update, switch N9 DL path)*
22. *(server: H-SMF → PSA UPF: N4 Modification, switch DL path)*
23. **UEContextReleaseCommand ← S-AMF** (on source gNB)
24. **UEContextReleaseComplete → S-AMF** (from source gNB)

Changes required in [n2-handover-hr-test.c](tests/roaming/n2-handover-hr-test.c):
1. After HandoverRequired (step 1), read HandoverRequest from `ngap_visiting` (step 8) — there may be a longer server-side delay due to V-SMF insertion chain
2. Add `testngap_build_uplink_ran_status_transfer()` after HandoverCommand (step 14)
3. Add read for DownlinkRANStatusTransfer on `ngap_visiting` (step 16), using `testngap_handle_downlink_ran_status_transfer()`
4. Update all 5 test functions with this corrected flow
5. Increase timeouts where needed (V-SMF insertion adds multiple SBI round-trips)
6. Verify HandoverRequest contains PDU sessions with N2 SM Info (V-UPF's N3 tunnel, not H-SMF's)

Also update [tests/common/ngap-build.c](tests/common/ngap-build.c) if the `testngap_build_handover_request_ack()` needs changes for the new flow (it currently includes `PDUSessionResourceAdmittedList`, which is correct for HR).

**Build & Test:**
```bash
ninja -C build
# Tests will FAIL at this point — expected
```

**Deviation recording:** Append any deviations to this plan file.

**Commit:** `git add tests/ && git commit -m "Phase 1: Rewrite HR test expected message flow for V-SMF insertion (§4.23.7.3)"`

---

### Phase 2: Fix Source AMF (H-AMF) — Direct CreateUEContext Without SMF Contact

The source AMF currently sends `UpdateSMContext(HO_REQUIRED)` to the SMF before CreateUEContext. For V-SMF insertion (UE at HPLMN → VPLMN), the UE has non-roaming sessions with a regular SMF — there's no V-SMF to contact. The source AMF should just send CreateUEContext directly.

**Changes:**

1. In [src/amf/ngap-handler.c](src/amf/ngap-handler.c#L3409) `ngap_handle_handover_required()`:
   - After detecting inter-PLMN handover, check if UE is currently roaming: `ogs_sbi_plmn_id_in_vplmn(&amf_ue->home_plmn_id)`
   - If UE is **NOT roaming** (at HPLMN): skip UpdateSMContext to SMF, send CreateUEContext directly
   - If UE **IS roaming** (V-SMF exists): keep current behavior for V-SMF change/delete (future work)
   - Store the source gNB's per-session `HandoverRequiredTransfer` in a new field `sess->transfer.handover_required_from_gnb` so it can be included in CreateUEContext for the target AMF to forward to V-SMF

2. In [src/amf/context.h](src/amf/context.h) `amf_sess_t.transfer`:
   - Add field `ogs_pkbuf_t *handover_required_from_gnb` to store the source gNB's raw HandoverRequiredTransfer per session
   - Add corresponding `AMF_SESS_STORE_N2_TRANSFER` / `AMF_SESS_CLEAR_N2_TRANSFER` handling

3. In [src/amf/namf-build.c](src/amf/namf-build.c#L105) `amf_namf_comm_build_create_ue_context()`:
   - When UE is not roaming (V-SMF insertion case): include per-session info with:
     - `sm_context_ref` pointing to the regular SMF (which will become the H-SMF)
     - `smf_uri` = the SMF's SBI URI (so target AMF can tell V-SMF where the H-SMF is)
     - N2 SM binary = the gNB's `HandoverRequiredTransfer` (NOT the SMF's `HandoverRequestTransfer`)
   - Add `smf_uri` field to the `PduSessionContext` in the multipart body (the OpenAPI model `OpenAPI_pdu_session_context_t` has `smf_service_instance_id` — check if it also has `smf_uri` or `hsmf_uri`)

4. In [src/amf/namf-handler.c](src/amf/namf-handler.c#L2559) `amf_namf_comm_handle_n2_info_notify()`:
   - For V-SMF insertion: source AMF no longer contacts SMF on completion (the H-SMF is managed by the V-SMF now)
   - Just send UEContextReleaseCommand to source gNB
   - Remove the `UpdateSMContext(COMPLETED)` to V-SMF (step 11 in old flow)

**Build & Test:**
```bash
sudo pkill -f "5gc -c" 2>/dev/null; sleep 2
ninja -C build
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml &
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml &
sleep 3
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test -v test1 > tmp/hr_phase2.log 2>&1
# Verify LBO tests still pass:
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-lbo-test
```
**Note:** HR test will still fail (target AMF doesn't handle V-SMF yet), but LBO tests must pass.

**Deviation recording:** Append any deviations to this plan file.

**Commit:** `git add src/ lib/ tests/ && git commit -m "Phase 2: Source AMF sends CreateUEContext directly (no SMF contact for V-SMF insertion)"`

---

### Phase 3: Target AMF V-SMF Selection + CreateSMContext Chain

This is the largest phase. The target AMF (V-AMF) must: receive CreateUEContext → select V-SMF → send `CreateSMContext(hoState=PREPARING)` → wait for response → send HandoverRequest to target gNB.

**Changes:**

1. **Target AMF: CreateUEContext handler** — [src/amf/namf-handler.c](src/amf/namf-handler.c#L1985) `amf_namf_comm_handle_create_ue_context_request()`:
   - After decoding PDU session list, detect V-SMF insertion needed: `ogs_sbi_plmn_id_in_vplmn(&amf_ue->home_plmn_id)` returns `true` (UE is now roaming) AND `!sess->lbo_roaming_allowed` (home-routed)
   - Extract `smf_uri` (H-SMF URI) and `sm_context_ref` (H-SMF SM context ref) from each `PduSessionContext`
   - Store the gNB's `HandoverRequiredTransfer` from the N2 SM multipart per session
   - Instead of building HandoverRequest immediately, initiate V-SMF discovery and CreateSMContext for each PDU session
   - Defer the HandoverRequest until all V-SMF CreateSMContext responses are received

2. **Target AMF: V-SMF discovery** — Use `amf_sess_sbi_discover_and_send()` with `OGS_SBI_SERVICE_TYPE_NSMF_PDUSESSION` scoped to the local PLMN (001-01). The existing NRF discovery mechanism should find the SMF at `smf.5gc.mnc001.mcc001.3gppnetwork.org`.

3. **Target AMF: Build CreateSMContext request** — New function in [src/amf/nsmf-build.c](src/amf/nsmf-build.c) (or extend existing `amf_nsmf_pdusession_build_create_sm_context()`):
   - Set `SmContextCreateData`:
     - `supi`, `pei`, `s_nssai`, `dnn`, `serving_nf_id`, `guami`, `serving_network`
     - `ho_state = OpenAPI_ho_state_PREPARING`
     - `h_smf_uri` = H-SMF URI from CreateUEContext
     - `sm_context_ref` = SM context ID at H-SMF (so V-SMF knows where to find the session)
     - `target_id` = target gNB ID
   - Include N2 SM Info: the gNB's HandoverRequiredTransfer as multipart binary
   - Include N1 SM: may need a minimal NAS PDU or can be omitted for HO (check if SMF requires it)

4. **Target AMF: Handle CreateSMContext response** — New handler state (e.g., `AMF_CREATE_SM_CONTEXT_HANDOVER_PREPARING`):
   - Parse `SmContextCreatedData` response
   - Extract V-SMF's SM context ref (store in `sess->sm_context_ref` and `sess->sm_context_resource_uri`)
   - Extract N2 SM Info from response (V-UPF's N3 F-TEID as `PDUSessionResourceSetupRequestHOReq_Transfer`)
   - Store in `sess->transfer.handover_request`
   - When all sessions have responded (`AMF_SESSION_SYNC_DONE`): build and send NGAP HandoverRequest to target gNB

5. **New AMF state constants** in [src/amf/sbi-path.h](src/amf/sbi-path.h):
   - `AMF_CREATE_SM_CONTEXT_INTER_PLMN_HANDOVER_PREPARING` for the V-SMF CreateSMContext during HO

**Build & Test:**
```bash
sudo pkill -f "5gc -c" 2>/dev/null; sleep 2
ninja -C build
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml &
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml &
sleep 3
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test -v test1 > tmp/hr_phase3.log 2>&1
# Test will still fail if V-SMF doesn't handle CreateSMContext with hoState yet
```

**Deviation recording:** Append any deviations to this plan file.

**Commit:** `git add src/ && git commit -m "Phase 3: Target AMF V-SMF selection and CreateSMContext during HO"`

---

### Phase 4: V-SMF CreateSMContext with hoState=PREPARING

Implement the V-SMF side of `CreateSMContext(hoState=PREPARING)` in the SMF. This is a new code path in the existing CreateSMContext handler.

**Changes:**

1. **SMF CreateSMContext handler** — [src/smf/nsmf-handler.c](src/smf/nsmf-handler.c#L28) `smf_nsmf_handle_create_sm_context()`:
   - After parsing `SmContextCreateData`, check `sbi_message->SmContextCreateData->ho_state == OpenAPI_ho_state_PREPARING`
   - If hoState=PREPARING (V-SMF insertion during HO):
     - Extract `h_smf_uri` → store in `sess->h_smf_uri` (activates `HOME_ROUTED_ROAMING_IN_VSMF`)
     - Extract `sm_context_ref` (H-SMF SM context reference)
     - Skip N1 NAS message processing (no N1 SM during HO)
     - Skip UDM/PCF interaction (session QoS will come from H-SMF)
     - Initiate Nsmf_PDUSession_Create toward H-SMF with `ho_preparation_indication = true`

2. **V-SMF → H-SMF: Nsmf_PDUSession_Create** — Modify [src/smf/nsmf-build.c](src/smf/nsmf-build.c#L23) `smf_nsmf_pdusession_build_create_data()`:
   - Add `ho_preparation_indication = true` to `PduSessionCreateData` when triggered by HO
   - Include reference to existing session at H-SMF (SUPI + PDU Session ID)
   - May need to send a placeholder `vcn_tunnel_info` (V-UPF N9 tunnel not yet allocated)
   - OR: do the V-UPF N4 Establishment FIRST, then send Create to H-SMF with actual V-UPF N9 info

3. **V-SMF: Handle H-SMF Create Response** — Modify [src/smf/nsmf-handler.c](src/smf/nsmf-handler.c#L1688) `smf_nsmf_handle_created_data_in_vsmf()`:
   - For HO case: extract session QoS parameters and PSA UPF's N9 tunnel info from response
   - Use this info to select V-UPF and establish N4 Session with correct QoS and tunnel config
   - After N4 Establishment Response from V-UPF: respond to T-AMF with N2 SM Info containing V-UPF's N3 F-TEID

4. **V-SMF: V-UPF N4 Session Establishment** — Adapt existing V-UPF establishment code:
   - Create UL PDR: match on N3 from target gNB, forward to N9 toward PSA UPF
   - Create DL PDR: match on N9 from PSA UPF, forward to N3 toward target gNB
   - The N3 F-TEID is allocated by V-UPF → this is what goes in the N2 SM response to T-AMF

5. **V-SMF: Build N2 SM Info (HandoverRequestTransfer)** — New or adapted builder function:
   - Generate `PDUSessionResourceSetupRequestHOReq_Transfer` containing:
     - UL N3 GTP tunnel: V-UPF's N3 F-TEID (for target gNB)
     - QoS Flow Setup Request: QFI, QoS parameters from H-SMF session context
   - Encode as ASN.1 PER and include in CreateSMContext response

**Key design decision:** The `Nsmf_PDUSession_Context` (context retrieval) is combined into the `Nsmf_PDUSession_Create` response. The H-SMF returns session QoS + PSA UPF tunnel info as part of the Create response, avoiding a separate service endpoint.

**Build & Test:**
```bash
sudo pkill -f "5gc -c" 2>/dev/null; sleep 2
ninja -C build
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml &
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml &
sleep 3
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test -v test1 > tmp/hr_phase4.log 2>&1
# Check logs for V-SMF → H-SMF Create flow
```
**Deviation recording:** Append any deviations to this plan file.

**Commit:** `git add src/ lib/ && git commit -m "Phase 4: V-SMF CreateSMContext(PREPARING) with H-SMF Create + V-UPF establishment"`

---

### Phase 5: H-SMF Handling of V-SMF Insertion During Handover

The H-SMF (regular SMF at 999-70) must handle `Nsmf_PDUSession_Create` from the new V-SMF for an **existing** session. Currently, the H-SMF Create handler only creates **new** sessions.

**Changes:**

1. **H-SMF Create handler** — [src/smf/nsmf-handler.c](src/smf/nsmf-handler.c#L1235) `smf_nsmf_handle_create_data_in_hsmf()`:
   - Check `PduSessionCreateData->ho_preparation_indication`
   - If `ho_preparation_indication = true`:
     - Find EXISTING session by SUPI + PDU Session ID (instead of creating new)
     - Store V-SMF's callback URI: `sess->vsmf_pdu_session_uri` (activates `HOME_ROUTED_ROAMING_IN_HSMF`)
     - Store V-SMF client info
     - Return session context: QoS rules, QFIs, session AMBR, S-NSSAI, DNN
     - Return PSA UPF's current tunnel info (N9 endpoint for V-UPF to connect to, or N3 endpoint if converting from non-roaming)
     - Send 201 response with `PduSessionCreatedData` containing the above info

2. **Session routing change** in [src/smf/smf-sm.c](src/smf/smf-sm.c#L600):
   - Currently `POST /pdu-sessions` always creates new session via `smf_sess_add_by_pdu_session()`
   - Add check: if `ho_preparation_indication`, try `smf_sess_find_by_supi_and_psi()` first
   - If existing session found: dispatch to modified `smf_nsmf_handle_create_data_in_hsmf()` for insertion
   - If not found: error (session should exist at H-SMF)

3. **PSA UPF tunnel conversion** — When H-SMF transitions from non-roaming to H-SMF mode:
   - Previously: PSA UPF had N3 tunnel directly to source gNB
   - Now: PSA UPF needs N9 tunnel to V-UPF
   - This conversion may happen during preparation (optional) or execution (mandatory)
   - For preparation: PSA UPF may not need modification yet (DL still goes to source gNB)
   - For execution: PSA UPF switches DL to V-UPF via N9

4. **Build H-SMF Create Response** — Modify/add response builder to include:
   - Session QoS parameters (QFI list, QoS characteristics)
   - PSA UPF's current GTP-U tunnel endpoint info
   - 201 status with `PduSessionCreatedData`
5. Build & Test (Remember to verify test cases pass and pcap files show correct messages)
6. Record deviation from the plan to end of plan file
7. Git commit

**Build & Test:**
```bash
sudo pkill -f "5gc -c" 2>/dev/null; sleep 2
ninja -C build
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml &
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml &
sleep 3
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test -v test1 > tmp/hr_phase5.log 2>&1
# At this point test1 should progress past HandoverRequired → HandoverRequest
# Check pcap for V-SMF→H-SMF SBI traffic through SEPP
sudo pkill -f "5gc -c"
```

**Deviation recording:** Append any deviations to this plan file.

**Commit:** `git add src/ && git commit -m "Phase 5: H-SMF handles V-SMF insertion for existing sessions during HO"`

---

### Phase 6: HandoverRequestAck → V-SMF UpdateSMContext(PREPARED) → CreateUEContext 201

After the target gNB responds with HandoverRequestAck, the target AMF must: send UpdateSMContext(PREPARED) to V-SMF → V-SMF sets up forwarding tunnels and coordinates with H-SMF → target AMF sends CreateUEContext 201 to source AMF.

**Changes:**

1. **Target AMF HandoverRequestAck handler** — [src/amf/ngap-handler.c](src/amf/ngap-handler.c#L3750) `ngap_handle_handover_request_ack()`:
   - For inter-AMF V-SMF insertion case:
     - Extract per-session `HandoverRequestAcknowledgeTransfer` (target gNB's N3 F-TEID)
     - Send `UpdateSMContext(hoState=PREPARED)` to V-SMF for each PDU session with the N2 SM Info
     - Defer the CreateUEContext 201 response until V-SMF responds
   - New state: `AMF_UPDATE_SM_CONTEXT_INTER_PLMN_HANDOVER_PREPARED`

2. **V-SMF UpdateSMContext(PREPARED) handler** — [src/smf/nsmf-handler.c](src/smf/nsmf-handler.c):
   - Parse `n2SmInfoType=HANDOVER_REQ_ACK` with the target gNB's N3 info
   - Store target gNB's N3 F-TEID in `sess->handover.gnb_n3_teid/ip`
   - Optionally set up indirect forwarding tunnels (if indirect forwarding requested)
   - Coordinate with H-SMF: send `UpdateSMContext` to H-SMF for forwarding tunnel setup if needed
   - Generate `HandoverCommandTransfer` N2 SM Info containing DL forwarding tunnel info
   - Respond to T-AMF with `hoState=PREPARED` and `n2SmInfoType=HANDOVER_CMD`

3. **Target AMF: Handle V-SMF PREPARED response** — [src/amf/nsmf-handler.c](src/amf/nsmf-handler.c):
   - New state handler for `AMF_UPDATE_SM_CONTEXT_INTER_PLMN_HANDOVER_PREPARED`
   - Store HandoverCommandTransfer in `sess->transfer.handover_command`
   - When all sessions synced: build and send CreateUEContext 201 Response to S-AMF
   - Include per-session N2 SM Info (HandoverCommandTransfer) and TargetToSource container

4. **Source AMF: Handle CreateUEContext 201** — [src/amf/namf-handler.c](src/amf/namf-handler.c#L2333) `amf_namf_comm_handle_create_ue_context_response()`:
   - For V-SMF insertion case (UE was at HPLMN): no UpdateSMContext to any SMF needed
   - Directly send HandoverCommand to source gNB with the N2 SM from the 201 response
5. Build & Test (Remember to verify test cases pass and pcap files show correct messages)
6. Record deviation from the plan to end of plan file
7. Git commit

**Build & Test:**
```bash
sudo pkill -f "5gc -c" 2>/dev/null; sleep 2
ninja -C build
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml &
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml &
sleep 3
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test -v test1 > tmp/hr_phase6.log 2>&1
# Test should now get past HandoverCommand
```

**Deviation recording:** Append any deviations to this plan file.

**Commit:** `git add src/ && git commit -m "Phase 6: V-SMF PREPARED + CreateUEContext 201 + HandoverCommand"`

---

### Phase 7: Execution Phase — COMPLETED + Data Path Switch

After HandoverNotify, the target AMF sends UpdateSMContext(COMPLETED) to V-SMF, which switches the data path through V-UPF and H-SMF.

**Changes:**

1. **Target AMF: HandoverNotify** — [src/amf/ngap-handler.c](src/amf/ngap-handler.c#L4799):
   - Send N2InfoNotify(HANDOVER_COMPLETED) to source AMF (already exists)
   - Send `UpdateSMContext(hoState=COMPLETED)` to V-SMF for each HR session
   - New state: `AMF_UPDATE_SM_CONTEXT_INTER_PLMN_HANDOVER_COMPLETED_AT_TARGET`

2. **V-SMF UpdateSMContext(COMPLETED) handler** — [src/smf/nsmf-handler.c](src/smf/nsmf-handler.c#L998):
   - N4 Modification to V-UPF: update DL FAR to send to target gNB's N3 F-TEID (from `handover.gnb_n3_teid`)
   - Send `Nsmf_PDUSession_Update` to H-SMF with V-UPF's DL CN (N9) tunnel info and Handover Complete indication
   - After H-SMF response: clear handover state, respond to T-AMF

3. **H-SMF: Handle Nsmf_PDUSession_Update from V-SMF** — [src/smf/nsmf-handler.c](src/smf/nsmf-handler.c):
   - In `smf_nsmf_handle_update_data_in_hsmf()`:
     - Receive V-UPF's N9 tunnel info
     - N4 Modification to PSA UPF: switch DL forwarding from old N3 (source gNB) to N9 (V-UPF)
     - Send end markers on old path
     - Respond to V-SMF

4. **Source AMF: Handle N2InfoNotify** — Simplified from current:
   - Just send UEContextReleaseCommand to source gNB
   - No UpdateSMContext to any SMF (H-SMF is managed by V-SMF now)

5. **Source AMF: After UEContextReleaseComplete**:
   - Clean up source UE context
   - The old N3 tunnel (source gNB → PSA UPF) is no longer used
   - PSA UPF forwarding rules are updated by H-SMF to use N9
5. Build & Test (Remember to verify test cases pass and pcap files show correct messages)
6. Record deviation from the plan to end of plan file
7. Git commit

**Build & Test:**
```bash
sudo pkill -f "5gc -c" 2>/dev/null; sleep 2
ninja -C build
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml &
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml &
sleep 3
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test -v test1 > tmp/hr_phase7.log 2>&1
# test1 should now pass end-to-end
# Also verify LBO:
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-lbo-test
```

**Deviation recording:** Append any deviations to this plan file.

**Commit:** `git add src/ && git commit -m "Phase 7: V-SMF COMPLETED + data path switch through V-UPF + H-SMF N4 modification"`

---

### Phase 8: RANStatusTransfer Forwarding

Enable RANStatusTransfer forwarding for inter-AMF HR handover to preserve PDCP sequence numbers for seamless handover.

**Changes:**

1. **Source AMF: Forward UplinkRANStatusTransfer** — [src/amf/ngap-handler.c](src/amf/ngap-handler.c#L4636):
   - Remove the early return for `amf_ue->inter_amf_handover`
   - Instead of sending DownlinkRANStatusTransfer directly (intra-AMF path), encode the `RANStatusTransfer_TransparentContainer` as NGAP binary
   - Send via `N2InfoNotify` with `n2InfoClass = RAN_STATUS_TRANSFER` (or a suitable indicator) to the target AMF through SEPP

2. **New N2InfoNotify type for RANStatusTransfer** — [src/amf/sbi-path.c](src/amf/sbi-path.c#L724):
   - New builder: `amf_namf_comm_build_n2_info_notify_ran_status_transfer()` to create HTTP request with NGAP RANStatusTransfer payload as multipart
   - Similar to existing `amf_sbi_send_n2_info_notify()` but with different `notifyReason`/`n2InfoClass`

3. **Target AMF: Handle N2InfoNotify(RAN_STATUS_TRANSFER)** — [src/amf/namf-handler.c](src/amf/namf-handler.c#L2575):
   - Add new branch in `amf_namf_comm_handle_n2_info_notify()` for RAN_STATUS_TRANSFER
   - Extract NGAP binary from multipart
   - Decode `RANStatusTransfer_TransparentContainer`
   - Call `ngap_send_downlink_ran_status_transfer()` to target gNB

4. **Test update** — Already handled in Phase 1 (test sends UplinkRANStatusTransfer, expects DownlinkRANStatusTransfer)
5. Build & Test (Remember to verify test cases pass and pcap files show correct messages)
6. Record deviation from the plan to end of plan file
7. Git commit

**Build & Test:**
```bash
sudo pkill -f "5gc -c" 2>/dev/null; sleep 2
ninja -C build
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml &
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml &
sleep 3
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test -v test1 > tmp/hr_phase8.log 2>&1
# Verify RANStatusTransfer in pcap
```

**Deviation recording:** Append any deviations to this plan file.

**Phase 8 Deviations (recorded 2025-02-24):**
1. **Critical bug fix in CreateUEContext handler (namf-handler.c)**: The T-AMF's
   `amf_ue->home_plmn_id`, `guami`, `nr_tai`, and `nr_cgi` were never populated
   during CreateUEContext processing. This caused `ogs_sbi_plmn_id_in_vplmn()` to
   fail with "No MCC" (MCC=0) and V-SMF NRF discovery to fail with "No NF-Instance".
   Fixed by parsing `home_plmn_id` from `CreateData->serving_network`, setting
   `guami` from `amf_self()->served_guami[0]`, and deriving `nr_tai`/`nr_cgi` from
   the target gNB's supported TA list. This is technically a Phase 2 bug but was
   only discovered during Phase 8 testing with the correct 2×12 NF test infrastructure.
2. **N2InfoNotify uses `amf_ue_sbi_discover_and_send()` with NRF discovery** instead
   of a direct send function like the existing `amf_sbi_send_n2_info_notify()`.
   This routes through SEPP correctly for cross-PLMN communication. The build
   function `amf_namf_comm_build_n2_info_notify_ran_status()` matches the
   `amf_ue_sbi_discover_and_send` callback signature.
3. **State constant**: Added `AMF_NAMF_COMM_N2_INFO_NOTIFY_RAN_STATUS = 30` in
   sbi-path.h with response handling in gmm-sm.c (registered state).

**Commit:** `git add src/ tests/ && git commit -m "Phase 8: RANStatusTransfer forwarding via N2InfoNotify for inter-AMF HO"`

---

### Phase 9: Cancel/Failure Paths for V-SMF Insertion

Implement cancel and failure handling for the V-SMF insertion case.

**Changes:**

1. **Handover Cancel** (test4):
   - Source gNB sends HandoverCancel to S-AMF
   - S-AMF sends CreateUEContext cancel/error to T-AMF (or the cancel arrives after 201)
   - T-AMF must send `UpdateSMContext(hoState=CANCELLED)` to V-SMF
   - V-SMF: rollback — release V-UPF N4 session, send Nsmf_PDUSession_Release to H-SMF
   - H-SMF: rollback — remove V-SMF reference, revert to non-roaming mode

2. **Handover Failure** (test5):
   - Target gNB sends HandoverFailure to T-AMF
   - T-AMF responds with error to deferred CreateUEContext
   - T-AMF must release V-SMF context: `ReleaseSMContext` to V-SMF
   - V-SMF: release V-UPF, send release to H-SMF

3. **V-SMF UpdateSMContext(CANCELLED)** — [src/smf/nsmf-handler.c](src/smf/nsmf-handler.c#L1062):
   - Extend existing CANCELLED handler to also handle the V-SMF insertion case
   - Release V-UPF N4 session
   - Send Nsmf_PDUSession_Release to H-SMF to unregister V-SMF

4. Update test4 and test5 in [n2-handover-hr-test.c](tests/roaming/n2-handover-hr-test.c) for the V-SMF insertion flow
5. Build & Test (Remember to verify test cases pass and pcap files show correct messages)
6. Record deviation from the plan to end of plan file
7. Git commit

**Build & Test:**
```bash
sudo pkill -f "5gc -c" 2>/dev/null; sleep 2
ninja -C build
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml &
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml &
sleep 3
# Run all HR tests:
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test
# Run all LBO tests:
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-lbo-test
```

**Deviation recording:** Append any deviations to this plan file.

**Commit:** `git add src/ tests/ && git commit -m "Phase 9: Cancel/failure rollback for V-SMF insertion"`

---

### Phase 10: Documentation, Pcap Verification, Final Testing

1. **Update** [docs/interplmn-n2-handover-pcap-verification.md](docs/interplmn-n2-handover-pcap-verification.md):
   - Document the correct V-SMF insertion message flow with exact packet IPs
   - Add expected SBI traffic: T-AMF → V-SMF CreateSMContext, V-SMF → H-SMF Create (through SEPP), UpdateSMContext(PREPARED/COMPLETED)
   - Add RANStatusTransfer verification steps
   - Add V-UPF N4 traffic verification

2. **Update** [docs/interplmn-n2-handover-limitations.md](docs/interplmn-n2-handover-limitations.md):
   - Remove "RANStatusTransfer Skipped" limitation (now implemented for HR)
   - Update V-SMF interaction description (now follows §4.23.7.3)
   - Add new limitations:
     - V-SMF insertion only (no V-SMF change/deletion yet)
     - Nsmf_PDUSession_Context combined with Create (simplified)
     - Indirect forwarding tunnel setup: simplified (may not handle all cases)
     - No source I-SMF/I-UPF handling

3. **Run comprehensive tests:**
   ```bash
   sudo pkill -f "5gc -c" 2>/dev/null; sleep 2
   ninja -C build
   sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml &
   sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml &
   sleep 3
   # All roaming tests:
   ./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml
   # Capture pcap:
   sudo tcpdump -i lo -w tmp/hr_final.pcap &
   ./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test
   sudo pkill tcpdump
   # Analyze pcap:
   tshark -r tmp/hr_final.pcap -Y "ngap || (http2 && (http2.header.value contains namf-comm || http2.header.value contains nsmf-pdusession))" -T fields -e frame.number -e ip.src -e ip.dst -e ngap.procedureCode -e http2.header.value
   ```

4. **Verify pcap shows:**
   - CreateUEContext: S-AMF (127.0.1.5) → SEPP1 → SEPP2 → SCP2 → T-AMF (127.0.2.5)
   - CreateSMContext: T-AMF → SCP2 → V-SMF (127.0.2.4)
   - V-SMF → H-SMF Create: V-SMF (127.0.2.4) → SCP2 → SEPP2 → SEPP1 → SCP1 → H-SMF (127.0.1.4)
   - HandoverRequest/Ack: T-AMF (127.0.2.5) ↔ target gNB (127.0.0.3)
   - RANStatusTransfer: source gNB → S-AMF → SEPP → T-AMF → target gNB
   - N2InfoNotify: T-AMF → SEPP → S-AMF
   - V-UPF N4 sessions on 127.0.2.7
5. Build & Test (Remember to verify test cases pass and pcap files show correct messages)
6. Record deviation from the plan to end of plan file
7. Git commit

**Deviation recording:** Append any deviations to this plan file.

**Commit:** `git add docs/ tests/ && git commit -m "Phase 10: Documentation, pcap verification, final testing"`

---

### Shutdown / Build / Restart / Run Tests Template

```bash
# 1. Shutdown all running NFs
sudo pkill -f "5gc -c" 2>/dev/null
sleep 2

# 2. Build
ninja -C build

# 3. Restart NFs (Home PLMN in terminal 1)
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml &

# 4. Restart NFs (Visiting PLMN in terminal 2)
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml &

# 5. Wait for NFs to start
sleep 3

# 6. Run tests
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test -e info

# 7. Record deviations
# Append deviations to this plan file under "Implementation Deviations" section
```

---

## Verification

1. All 5 HR test cases pass: `n2-handover-hr-test` shows 5/5 PASS
2. All 5 LBO test cases still pass: `n2-handover-lbo-test` shows 5/5 PASS
3. Pcap analysis: V-SMF insertion visible (CreateSMContext → V-SMF → H-SMF chain), RANStatusTransfer forwarded, SEPP routing for all inter-PLMN SBI
4. Data path verified: V-UPF N4 sessions established, PSA UPF N9 tunnel configured
5. Documentation updated: pcap verification + limitations

## Key Decisions

- **V-SMF insertion only**: Implementing the UE-at-HPLMN-to-VPLMN direction (§4.23.7.3 insertion). V-SMF change and deletion are future work.
- **Context retrieval combined with Create**: `Nsmf_PDUSession_Context` is NOT implemented as a separate service. Instead, the `Nsmf_PDUSession_Create` with `ho_preparation_indication=true` returns session context info. This reduces complexity by one SBI round-trip while maintaining the same information flow.
- **H-SMF session lookup for insertion**: The H-SMF `POST /pdu-sessions` handler is extended to find existing sessions (by SUPI + PDU Session ID) when `ho_preparation_indication=true`, rather than always creating new sessions.
- **Source AMF simplification**: When UE is at HPLMN (not roaming), the source AMF sends CreateUEContext directly without contacting any SMF. The gNB's HandoverRequiredTransfer is forwarded via CreateUEContext to the target AMF.
- **RANStatusTransfer**: Forwarded via N2InfoNotify SBI call from S-AMF to T-AMF, then delivered to target gNB. This enables seamless handover with PDCP SN preservation for HR.
- **PSA UPF path switch timing**: PSA UPF DL path is switched during execution phase (COMPLETED), not during preparation. This simplifies the preparation flow.
- **All changes gated on roaming detection**: The existing LBO code path (`!ogs_sbi_plmn_id_in_vplmn()` at source AMF → direct CreateUEContext) remains unchanged, ensuring LBO tests pass.

---

## Implementation Deviations

### Phase 5 Deviations

1. **BugFix in `src/amf/namf-build.c` — PduSessionContext `smf_service_instance_id`**:
   The plan did not account for the S-AMF's CreateUEContext builder passing the wrong URL as `smf_service_instance_id` in PduSessionContext. It was set to `sess->sm_context_resource_uri` (which resolves to `<apiroot>/nsmf-pdusession/v1/sm-contexts/<ref>`). The T-AMF stored this as the H-SMF URI and passed it to the V-SMF, which then POSTed `PduSessionCreateData` to the sm-contexts endpoint instead of the pdu-sessions endpoint. This caused the H-SMF to try parsing it as `SmContextCreateData`, failing with `serving_nf_id` parse error, and the V-SMF to crash when the response came back with resource name `sm-contexts`. **Fix**: Extract the apiroot from `sm_context_resource_uri` using `ogs_sbi_getaddr_from_uri()` + `ogs_sbi_client_apiroot()` and construct the proper `<apiroot>/nsmf-pdusession/v1/pdu-sessions` URL.

2. **`smf_sbi_send_pdu_session_created_data_ho()` is a full clone (~250 lines) of `smf_sbi_send_pdu_session_created_data()` minus N1 SM**: Rather than adding conditional logic to the existing function, a separate function was created to avoid complexity in the already-large response builder. The HO version omits `n1SmInfoToUe`/`n1SmBufToUe` since there is no NAS SM message during handover preparation.

3. **`smf_nsmf_handle_created_data_in_vsmf()` modifications**: Two sections wrapped in `if (!sess->ho_state_preparing)` — (a) N1 SM check/decode around lines 1920-1940, and (b) NAS message handling + PFCP modification around lines 2230-2258. During HO, the V-SMF skips N1 SM parsing and does not send PFCP modification request (no QoS flow modification needed during preparation).

4. **Deferred 201 to T-AMF**: In `gsm-sm.c` operational state `OGS_FSM_ENTRY_SIG`/`SBI_CLIENT DEFAULT`, after `smf_nsmf_handle_created_data_in_vsmf()` succeeds for HO, the V-SMF calls `smf_sbi_send_sm_context_created_data_ho_preparing()` to send the deferred 201 response to the T-AMF. This was implied but not explicitly detailed in the plan.

### Phase 6 Deviations

1. **No separate helper function for CreateUEContext 201**: The plan suggested the T-AMF
   handle V-SMF PREPARED and coordinate with H-SMF for forwarding tunnel setup. In practice,
   the V-SMF's existing `ngap_handle_handover_request_ack()` handler already works correctly
   for the V-SMF case: it decodes the HandoverRequestAcknowledgeTransfer, stores the target
   gNB's N3 F-TEID, and builds a HandoverCommandTransfer response. No separate H-SMF
   coordination was needed during PREPARED (forwarding tunnels are optional and not used
   in this simplified flow).

2. **CreateUEContext 201 built inline in nsmf-handler.c**: Rather than creating a shared
   helper function callable from both ngap-handler.c and nsmf-handler.c, the 201 response
   builder is inlined in the `AMF_UPDATE_SM_CONTEXT_INTER_PLMN_HANDOVER_PREPARED` handler
   in `nsmf-handler.c`. The ngap-handler.c only retains a simplified fallback for the
   edge case of no admitted PDU sessions.

3. **S-AMF stores per-session HandoverCommandTransfer from 201**: The plan item 4
   (S-AMF handling) now stores per-session N2 SM from the CreateUEContext 201 response
   into `sess->transfer.handover_command` before calling `ngap_send_handover_command()`.
   This ensures the HandoverCommand sent to the source gNB includes the
   PDUSessionResourceHandoverList with HandoverCommandTransfer per session.

4. **New state `AMF_UPDATE_SM_CONTEXT_INTER_PLMN_HANDOVER_PREPARED = 32`**: Added in
   `sbi-path.h`. Error handling sends 500 error on the deferred CreateUEContext stream
   if any V-SMF PREPARED response fails.

**Phase 7 Deviations (recorded 2025-02-25):**

1. **V-SMF/H-SMF COMPLETED handler already existed**: The existing COMPLETED handler
   in `smf/nsmf-handler.c` already handles N2_HANDOVER with HOME_ROUTED_ROAMING flags,
   so no SMF code changes were needed for the V-SMF→H-SMF update path. Only the AMF
   needed new code to trigger UpdateSMContext(COMPLETED) for HR sessions.

2. **H-SMF state machine exception fixed**: Phase 5's `smf_nsmf_handle_create_data_in_hsmf_ho()`
   had an unconditional `OGS_FSM_TRAN(s, smf_gsm_state_exception)` fall-through after
   successful HO handling in `gsm-sm.c`. Fixed by adding transition to exception only
   on failure, keeping operational state on success.

3. **Source AMF: skip H-SMF release for V-SMF insertion sessions**: During
   HandoverNotify at S-AMF (namf-handler.c), for V-SMF insertion sessions the S-AMF
   now uses `CLEAR_SESSION_CONTEXT(sess)` instead of `amf_sbi_send_release_session()`
   since the H-SMF session is now managed by the new V-SMF at the target PLMN.

4. **New state `AMF_UPDATE_SM_CONTEXT_INTER_PLMN_HANDOVER_COMPLETED_AT_TARGET = 35`**:
   Added in `sbi-path.h` for the T-AMF's V-SMF COMPLETED response handling. Error
   handler just logs a warning (handover is already committed at this point).

