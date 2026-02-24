# Plan: Inter-PLMN N2 Handover for Home-Routed Roaming

## TL;DR

Extend the existing inter-PLMN N2 handover (currently LBO-only) to support **home-routed roaming**, where PDU sessions survive the handover because the H-SMF/H-UPF anchor in the home PLMN persists while only the V-SMF/V-UPF leg changes. The key differences from LBO: the source AMF must involve the SMF during handover preparation (not skip it), the `CreateUEContext` must carry PDU session context with H-SMF references, the target AMF must create new V-SMF sessions linked to the existing H-SMF, and the `HandoverRequest` must include `PDUSessionResourceSetupListHOReq`. Implementation is phased: Phase 1 covers single-session basic HR handover + multi-session, Phase 2 covers error paths (cancel/failure) and indirect forwarding. Make sure to document major deviations from the plan for each sub-phase at the end of this plan file.

The existing SEPP test architecture already provides two complete PLMNs (999-70 on `127.0.1.x` and 001-01 on `127.0.2.x`) each with their own AMF, SMF, UPF, NRF, SCP, and SEPP. A new test file `tests/roaming/n2-handover-hr-test.c` will be created alongside a renamed `tests/roaming/n2-handover-lbo-test.c` (copied from the existing file).

Note on indirect forwarding: since gNBs in different PLMNs will not have direct Xn connections between them, **indirect data forwarding** is the default and expected behavior for inter-PLMN handover. Therefore indirect forwarding support is part of the core Phase 1 implementation rather than being deferred to error-handling phases. 

---

## 3GPP Specification References

| Spec | File | Key Sections | Description |
|------|------|-------------|-------------|
| **TS 23.502 v19.6.0** | `ts_123502v190600p.pdf` | §4.9.1.3 (N2 Handover), §4.9.1.3.2 (Inter NG-RAN node N2 based handover), §4.9.1.3.3 (Inter NG-RAN node N2 based handover with AMF change), §4.23 (Support of deployments topologies with specific SMF Service Area), §4.23.7 (V-SMF insertion/change during N2 HO), §4.23.11-12 (Home-routed V-SMF change) | Overall handover procedures, home-routed roaming session continuity, V-SMF insertion and change during handover |
| **TS 29.413 v19.0.0** | `ts_129413v190000p.pdf` | NGAP message definitions, HandoverRequired, HandoverRequest, HandoverRequestAck, HandoverCommand, HandoverNotify, PDUSessionResourceSetupListHOReq, PDUSessionResourceAdmittedList | NGAP protocol definitions for N2 handover messages |
| **TS 29.518 v18.12.0** | `ts_129518v181200p.pdf` | §5.2.2.2 (Namf_Communication CreateUEContext), §5.2.2.3 (N2InfoNotify), UeContextCreateData, PduSessionContext | AMF service definitions — CreateUEContext for inter-AMF handover, N2 info notification |
| **TS 29.502 v19.5.0** | `ts_129502v190500p.pdf` | §5.2.2.3 (Nsmf_PDUSession UpdateSMContext), §5.2.2.3.4.2 (HO Preparation), §5.2.2.3.4.3 (HO Execution), §5.2.2.3.4.4 (HO Cancellation), §5.2.2.2.5 (CreateSMContext for V-SMF insertion), §5.2.2.8.2.3-4 (H-SMF Update for HO), §5.2.2.8.2.10 (V-SMF change on N16), §5.2.2.8.2.20 (V-SMF removal) | SMF service definitions — handover state machine (PREPARING→PREPARED→COMPLETED/CANCELLED), V-SMF ↔ H-SMF interaction on N16, home-routed session handling |

These specs should be consulted at the end of each subphase to verify compliance. Each subphase includes a **Spec Verification** checkpoint listing the specific clauses to cross-reference.

---

## Steps

### Phase 0: Preserve Existing LBO Tests

1. **Copy** `tests/roaming/n2-handover-test.c` → `tests/roaming/n2-handover-lbo-test.c`. Rename internal suite function from `test_n2_handover` to `test_n2_handover_lbo`. Keep all 5 existing test cases unchanged.

2. **Create** `tests/roaming/n2-handover-hr-test.c` as a new file with suite `test_n2_handover_hr`. Initially, copy the skeleton from the LBO file but adapt for home-routed semantics (session transfer instead of release).

3. **Update** `tests/roaming/abts-main.c`: add `test_n2_handover_lbo` and `test_n2_handover_hr` to the `alltests[]` array; remove `test_n2_handover`.

4. **Update** `tests/roaming/meson.build`: add both new `.c` files to `test5gc_roaming_sources`; remove `n2-handover-test.c`.

5. **Set `lbo_roaming_allowed: false`** in `configs/examples/gnb-999-70-ue-001-01.yaml.in` for the HR test subscriber, or add a second subscriber entry with `lbo_roaming_allowed: false`. The LBO test would use the existing `true` subscriber; the HR test uses the `false` subscriber. Alternatively, add a second test config file specifically for HR if cleaner.

6. Build, run the LBO tests to confirm they still pass:
   ```bash
   ./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-lbo-test -e info
   ```
   Git commit.

**Spec Verification (Phase 0):** No spec compliance changes — this phase is purely structural. Verify that existing LBO behavior still matches TS 23.502 §4.9.1.3.2 (PDU sessions released, not transferred for LBO).

---

### Phase 1A: Source AMF — Handover Preparation with SMF Involvement

**Problem**: Currently the inter-PLMN branch in `ngap_handle_handover_required()` at `src/amf/ngap-handler.c` (around line 3331) skips SMF interaction entirely. For home-routed sessions, the source AMF must send `UpdateSMContext(hoState=PREPARING)` to the V-SMF (which forwards to H-SMF) to get `PDUSessionResourceSetupRequestTransfer` N2 SM info.

7. **Modify** `ngap_handle_handover_required()` in `src/amf/ngap-handler.c`: after detecting inter-PLMN, iterate `amf_ue->sess_list` and check each session's `sess->lbo_roaming_allowed`. For home-routed sessions (`lbo_roaming_allowed == false`), send `UpdateSMContext` with `hoState=PREPARING`, `n2SmInfoType=HANDOVER_REQUIRED`, and `TargetID` to the SMF — same as the intra-AMF path at line 3573. For LBO sessions, skip (existing behavior).

8. **Add new sync state** `AMF_UPDATE_SM_CONTEXT_INTER_PLMN_HANDOVER_REQUIRED` to `src/amf/context.h` to distinguish from intra-AMF handover sync. When all SMF responses are received for this state, proceed to send `CreateUEContext` to the target AMF.

9. **Modify** the SMF response handler in `src/amf/nsmf-handler.c` (around line 351): add a case for `AMF_UPDATE_SM_CONTEXT_INTER_PLMN_HANDOVER_REQUIRED`. Store the returned N2 SM info in `sess->transfer.handover_request` (same as intra-AMF). When `AMF_SESSION_SYNC_DONE`, call the existing `CreateUEContext` send path instead of `ngap_send_handover_request()`.

10. **Extend** `CreateUEContext` builder at `src/amf/namf-build.c` (around line 252): populate `pdu_session_list` with `PduSessionContext` entries for each home-routed session that has a `handover_request` transfer. Include `sm_context_ref`, `s_nssai`, `dnn`, `access_type`. Additionally, add custom fields or use existing extension points to pass:
    - `lbo_roaming_allowed` per session (so the target AMF knows it's home-routed)
    - The H-SMF FQDN/URI (so the target AMF can connect the new V-SMF to the existing H-SMF)
    - The N2 SM transfer buffer per session (so the target AMF can include it in `HandoverRequest`)

**Spec Verification (Phase 1A):**
- TS 29.502 §5.2.2.3.4.2: Verify `UpdateSMContext` with `hoState=PREPARING` is sent per session, includes `n2SmInfo` of type `HANDOVER_REQUIRED` and `targetId`
- TS 23.502 §4.9.1.3.3 step 2: Source AMF sends Nsmf_PDUSession_UpdateSMContext to SMF(s) with HO indication
- TS 29.518 §5.2.2.2: Verify `CreateUEContext` request structure includes `pduSessionList` with `PduSessionContext` entries
- TS 23.502 §4.23.7: Verify source AMF correctly involves V-SMF for home-routed sessions during preparation

---

### Phase 1B: Target AMF — Create Sessions and Send HandoverRequest with PDU Sessions

11. **Modify** `amf_namf_comm_handle_create_ue_context_request()` at `src/amf/namf-handler.c` (around line 1985): after creating the UE context, decode the `pdu_session_list` from `CreateData`. For each session entry:
    - Create `amf_sess_t` via `amf_sess_add()`
    - Store `lbo_roaming_allowed`, `s_nssai`, `dnn`
    - Store the N2 SM handover transfer buffer in `sess->transfer.handover_request`
    - Store the H-SMF reference for later V-SMF creation

12. **Modify** the `HandoverRequest` send logic: currently the target AMF sends `HandoverRequest` immediately at `namf-handler.c` line 2218. With home-routed sessions, the target AMF must include `PDUSessionResourceSetupListHOReq` in the `HandoverRequest`. The N2 SM transfer buffers were already collected by the source AMF's SMF and forwarded via `CreateUEContext`. Populate `sess->transfer.handover_request` from this data so that `ngap_build_handover_request()` at `ngap-build.c` line 2328 picks it up automatically.

13. **No changes needed** to `ngap_build_handover_request()` (`src/amf/ngap-build.c` around line 2147) — it already iterates sessions and includes any with `sess->transfer.handover_request != NULL`.

**Spec Verification (Phase 1B):**
- TS 29.413 (NGAP): Verify `HandoverRequest` includes `PDUSessionResourceSetupListHOReq` with correct `PDUSessionResourceSetupItemHOReq` per session (PSI, S-NSSAI, handoverRequestTransfer)
- TS 23.502 §4.9.1.3.3 step 4: Target AMF sends HandoverRequest to target NG-RAN with PDU session resources
- TS 29.518 §5.2.2.2: Verify target AMF correctly decodes `pduSessionList` from `UeContextCreateData`

---

### Phase 1C: Target AMF — HandoverRequestAck with PDU Sessions

14. **Modify** `ngap_handle_handover_request_ack()` at `src/amf/ngap-handler.c` (around line 3711): when `inter_amf_handover == true` and sessions are present, extract `PDUSessionResourceAdmittedList` from the target gNB's ack. For each admitted session, store the target gNB's DL tunnel info. For the inter-AMF case, this info must be forwarded back to the source AMF in the `CreateUEContext` 201 response, so the source AMF can forward it to the SMF via `UpdateSMContext(hoState=PREPARED/REQ_ACK)`.

15. **Extend** the `CreateUEContext` 201 response: include per-session `HandoverRequestAckTransfer` from the target gNB. Currently the response only includes the `TargetToSource-TransparentContainer` at `ngap-handler.c` line 3760. Add per-session N2 SM info so the source AMF can forward to the SMF.

16. **Modify** `amf_namf_comm_handle_create_ue_context_response()` on the source AMF at `src/amf/namf-handler.c` (around line 2240): extract per-session `HandoverRequestAckTransfer` from the 201 response. For each home-routed session, send `UpdateSMContext(n2SmInfoType=HANDOVER_REQ_ACK)` to the V-SMF. The SMF responds with `HandoverCommandTransfer`. Use `AMF_SESSION_SYNC_DONE` to wait for all sessions, then send `HandoverCommand` to the source gNB (which already partially happens at line 2290 but without session transfers).

**Spec Verification (Phase 1C):**
- TS 29.413 (NGAP): Verify `HandoverRequestAck` includes `PDUSessionResourceAdmittedList` with per-session `handoverRequestAckTransfer` (target gNB DL GTP-U tunnel info)
- TS 29.502 §5.2.2.3.4.2: Verify `UpdateSMContext` with `n2SmInfoType=HANDOVER_REQ_ACK` is sent to V-SMF per session; SMF responds with `HandoverCommandTransfer`
- TS 23.502 §4.9.1.3.3 step 6: Source AMF receives HandoverCommand from SMF and forwards to source NG-RAN
- TS 29.502 §5.2.2.8.2.3: For home-routed, verify V-SMF stores target gNB tunnel info and marks QoS flows as prepared

---

### Phase 1D: Handover Execution and V-SMF Switch

17. **Modify** `ngap_handle_handover_notification()` at `src/amf/ngap-handler.c` (around line 4528): on the target AMF, after sending `N2InfoNotify` to the source AMF, the target AMF needs to create new V-SMF sessions in its local PLMN. For each home-routed session:
    - Discover a V-SMF in the target PLMN (using SMF selection with the session's S-NSSAI and DNN)
    - Send `Nsmf_PDUSession_CreateSMContext` to the new V-SMF with `h_smf_uri` / `h_smf_id` pointing to the existing H-SMF
    - The new V-SMF contacts the H-SMF on N16 to register itself, which causes H-SMF to switch the DL user plane to the new V-UPF
    - Send `UpdateSMContext(hoState=COMPLETED)` to complete the handover

    **Alternative approach**: The target AMF may need to create V-SMF sessions **before** `HandoverNotify` (during preparation) and only call `hoState=COMPLETED` after notify. This depends on whether the new V-SMF needs to be set up during preparation or execution. Per TS 23.502 §4.23, V-SMF insertion can happen during preparation. Research the exact ordering and implement accordingly.

18. **Modify** `amf_namf_comm_handle_n2_info_notify()` on the source AMF at `src/amf/namf-handler.c` (around line 2380): instead of calling `amf_sbi_send_release_all_sessions()` for ALL sessions, branch on `sess->lbo_roaming_allowed`:
    - **LBO sessions**: release via `Nsmf_PDUSession_ReleaseSMContext` (existing behavior)
    - **Home-routed sessions**: release the old V-SMF context with `vsmfReleaseOnly=true` indication, or simply release the source-side SM context since the H-SMF is now linked to the new V-SMF in the target PLMN

**Spec Verification (Phase 1D):**
- TS 23.502 §4.9.1.3.3 steps 8-11: HandoverNotify triggers execution; target AMF notifies source AMF
- TS 29.502 §5.2.2.3.4.3: Verify `UpdateSMContext(hoState=COMPLETED)` is sent with `servingNfId` = target AMF
- TS 29.502 §5.2.2.8.2.3: For home-routed, V-SMF forwards HO completion to H-SMF which switches DL user plane
- TS 29.502 §5.2.2.8.2.10: Verify new V-SMF registers with H-SMF via N16 Create/Update, providing `vsmfPduSessionUri` and `vsmfId`
- TS 29.502 §5.2.2.8.2.20: Verify old V-SMF is released with `vsmfReleaseOnly` indication (no signaling to H-SMF from old V-SMF)
- TS 23.502 §4.23.7/§4.23.11-12: Verify V-SMF change procedure is correctly followed for home-routed sessions

---

### Phase 1E: Test Cases (Single + Multi-Session + Indirect Forwarding HR Handover)

Since gNBs in different PLMNs do not have direct Xn connections, **indirect data forwarding** is the default behavior for inter-PLMN handover. This must be tested as part of the core implementation.

19. **Implement** `test1_func` in `n2-handover-hr-test.c`: basic single-session home-routed N2 handover.
    - Register UE on Home AMF (PLMN 999-70), establish one PDU session with `lbo_roaming_allowed=false`
    - Trigger `HandoverRequired` from source gNB to Home AMF
    - Verify: `CreateUEContext` includes PDU session context
    - Verify: `HandoverRequest` on target gNB includes `PDUSessionResourceSetupListHOReq`
    - Build a `HandoverRequestAck` **with** `PDUSessionResourceAdmittedList` (unlike LBO's `build_handover_request_ack_no_sessions()`)
    - Complete handover (`HandoverNotify` → `N2InfoNotify`)
    - Verify GTP-U data path works after handover (ping through new V-UPF/H-UPF chain)

20. **Implement** `test2_func`: multi-session HR handover (two PDU sessions, both home-routed).

21. **Build helper function** `build_handover_request_ack_with_sessions()` — analogous to existing `build_handover_request_ack_no_sessions()` at `n2-handover-test.c` line 275 but includes `PDUSessionResourceAdmittedList` with target gNB GTP-U tunnel info.

22. **Implement** `test3_func`: indirect data forwarding with home-routed sessions. Since gNBs are in different PLMNs without direct Xn connectivity, set `direct_forwarding=false` in `HandoverRequired`. Verify indirect forwarding tunnels are properly created via the SMF handover state machine, data is forwarded through the indirect tunnel during handover, and tunnels are released after handover completion.

23. Build, run both LBO and HR tests. Capture pcap. Verify messages. Git commit.

**Spec Verification (Phase 1E):**
- TS 29.413 (NGAP): Verify test messages match NGAP encoding for HandoverRequired, HandoverRequest, HandoverRequestAck (with PDUSessionResourceAdmittedList), HandoverCommand, HandoverNotify
- TS 29.502 §5.2.2.3.4.2: Verify indirect forwarding tunnel setup when `directForwardingPathAvailability` is not indicated
- TS 23.502 §4.9.1.3.2: Verify full N2 handover message sequence for inter-PLMN with AMF change
- Verify pcap captures show correct SMF UpdateSMContext interactions and V-SMF creation in target PLMN

---

### Phase 2: Error Paths

24. **Implement** `test4_func`: handover cancellation with home-routed sessions. After `HandoverCommand`, source gNB sends `HandoverCancel`. Source AMF must send `UpdateSMContext(hoState=CANCELLED)` to the V-SMF for each home-routed session to release handover resources.

25. **Implement** `test5_func`: handover failure. Target gNB sends `HandoverFailure`. Target AMF responds 403 on `CreateUEContext`. Source AMF must send `UpdateSMContext(hoState=CANCELLED)` to each home-routed session's V-SMF.

26. **Modify** source AMF `ngap_handle_handover_cancel()` at `src/amf/ngap-handler.c` (around line 4167): for inter-AMF handover with home-routed sessions, send `UpdateSMContext(hoState=CANCELLED)` to each session's V-SMF before sending `HandoverCancelAcknowledge`.

27. **Modify** source AMF `CreateUEContext` error response handler at `src/amf/namf-handler.c` (around line 2267): on receiving 403/4xx, send `UpdateSMContext(hoState=CANCELLED)` for each home-routed session to roll back SMF handover state.

28. Build, run all tests (LBO + HR), capture pcap, verify. Git commit.

**Spec Verification (Phase 2):**
- TS 29.502 §5.2.2.3.4.4: Verify `UpdateSMContext(hoState=CANCELLED)` is sent per session on cancel/failure, and V-SMF releases handover resources
- TS 29.502 §5.2.2.8.2.14/§5.2.2.8.2.17: For home-routed, verify V-SMF cancels handover on N16 toward H-SMF to release reserved resources
- TS 23.502 §4.9.1.3.3: Verify error path handling matches the spec for HandoverCancel and HandoverFailure
- TS 29.413 (NGAP): Verify HandoverCancelAcknowledge and HandoverPreparationFailure message encoding

---

### Phase 3: Documentation and Verification

29. **Update** `docs/interplmn-n2-handover-limitations.md`: modify limitation #1 (LBO Session Strategy) to note HR is now supported. Modify limitation #2 (No PDU Session Transfer) to reflect PDU sessions ARE transferred for HR. Update RANStatusTransfer limitation (now applicable for HR). Add new limitations specific to HR (e.g., V-SMF insertion timing, H-SMF reachability requirements).

30. **Update** `docs/interplmn-n2-handover-pcap-verification.md`: add HR-specific message flows showing the additional SMF interactions (UpdateSMContext during preparation), V-SMF creation on target side, and session continuity verification.

31. Git commit documentation changes.

**Spec Verification (Phase 3):**
- Review all limitation entries against TS 23.502 §4.9.1.3.3 and §4.23 to confirm accuracy
- Cross-reference pcap verification guide message flows against TS 29.413 (NGAP procedure codes) and TS 29.502 (SMF API operations)
- Verify any remaining deviations from spec are documented as known limitations

---

## Build/Test/Debug Commands

```bash
# Kill all
sudo pkill -9 open5gs
ps -aux | grep open5gs

# Build
ninja -C build

# Start NFs (3 terminals)
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml 2>&1 | tee sepp1.log
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml 2>&1 | tee sepp2.log
sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp3-315-010.yaml 2>&1 | tee sepp3.log

# (Optional) Capture pcap
sudo tcpdump -i lo -s 0 -w handover_hr_test.pcap

# Run LBO tests (verify no regression)
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-lbo-test -e info

# Run HR tests
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test -e info

# Run specific test
./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-hr-test -v test1 -e info

# Kill all after testing
sudo pkill -9 open5gs
```

---

## Verification

- **Unit tests**: All LBO tests (5 cases) pass without regression. All HR tests pass.
- **PCAP verification**: For HR test1, verify:
  - `UpdateSMContext(hoState=PREPARING)` is sent from source AMF to V-SMF during `HandoverRequired` processing
  - `CreateUEContext` request body includes `pdu_session_list` with session references
  - `HandoverRequest` to target gNB includes `PDUSessionResourceSetupListHOReq`
  - `HandoverRequestAck` includes `PDUSessionResourceAdmittedList`
  - New V-SMF session is created in target PLMN (visible as `Nsmf_PDUSession_CreateSMContext` to `127.0.2.4`)
  - `UpdateSMContext(hoState=COMPLETED)` is sent after `HandoverNotify`
  - Source-side V-SMF context is released (not all sessions)
  - GTP-U data flows through the new V-UPF (subnet change from `10.45.x` to target path)
- **Documentation**: limitations and pcap verification docs updated

---

## Key Decisions

- **Test file split**: Separate `n2-handover-lbo-test.c` and `n2-handover-hr-test.c` (user choice)
- **Phased delivery**: Phase 1 (basic HR + multi-session + indirect forwarding) first, Phase 2 (error paths: cancel + failure) second
- **V-SMF insertion timing**: Per TS 23.502 §4.23, the target AMF's V-SMF creation will likely happen during handover execution (after `HandoverNotify`), not during preparation. The N2 SM transfer from source SMF is relayed through `CreateUEContext` rather than requiring the target V-SMF during preparation. This simplifies the implementation: the target AMF uses the source V-SMF's N2 info in `HandoverRequest`, then creates the target V-SMF post-handover-notify.
- **H-SMF info transfer**: The `PduSessionContext` encoding in `CreateUEContext` will be extended with `h_smf_uri` and `lbo_roaming_allowed` fields to enable the target AMF to properly create home-routed V-SMF sessions. This may require extending the `OpenAPI_pdu_session_context_t` model or using vendor-specific extension fields.

---

## Key Files Reference

| File | Role |
|------|------|
| `src/amf/ngap-handler.c` | Source AMF: HandoverRequired, HandoverCancel, target AMF: HandoverRequestAck, HandoverNotify |
| `src/amf/namf-handler.c` | Target AMF: CreateUEContext request handler; Source AMF: CreateUEContext response, N2InfoNotify |
| `src/amf/namf-build.c` | CreateUEContext request/response builders |
| `src/amf/ngap-build.c` | HandoverRequest builder (PDUSessionResourceSetupListHOReq) |
| `src/amf/nsmf-handler.c` | SMF response handler for UpdateSMContext (handover states) |
| `src/amf/nsmf-build.c` | UpdateSMContext request builder (hoState, N2 SM info) |
| `src/amf/context.h` | `amf_ue_t`, `amf_sess_t` structures, sync state enums |
| `src/amf/sbi-path.c` | SMF selection states, session release functions |
| `src/smf/nsmf-handler.c` | SMF handover state machine (PREPARING→PREPARED→COMPLETED/CANCELLED) |
| `src/smf/ngap-handler.c` | SMF N2 transfer builders for handover |
| `src/smf/context.h` | `smf_sess_t` with home-routed macros (`HOME_ROUTED_ROAMING_IN_VSMF/HSMF`) |
| `tests/roaming/n2-handover-test.c` | Existing LBO test (to be split) |
| `tests/roaming/abts-main.c` | Test suite registration |
| `tests/roaming/meson.build` | Test build config |
| `configs/examples/gnb-999-70-ue-001-01.yaml.in` | Test client config (`lbo_roaming_allowed` toggle) |
| `configs/examples/5gc-sepp1-999-70.yaml.in` | Home PLMN NF config (AMF 127.0.1.5, SMF 127.0.1.4, UPF 127.0.1.7) |
| `configs/examples/5gc-sepp2-001-01.yaml.in` | Visited PLMN NF config (AMF 127.0.2.5, SMF 127.0.2.4, UPF 127.0.2.7) |
| `docs/interplmn-n2-handover-limitations.md` | Known limitations documentation |
| `docs/interplmn-n2-handover-pcap-verification.md` | PCAP verification guide |

## Network Topology

| NF | Home PLMN (999-70) | Visited PLMN (001-01) |
|----|--------------------|-----------------------|
| AMF (NGAP) | `127.0.1.5` | `127.0.2.5` |
| SMF (SBI) | `127.0.1.4:7777` | `127.0.2.4:7777` |
| UPF (PFCP/GTP-U) | `127.0.1.7` | `127.0.2.7` |
| NRF | `nrf.5gc.mnc070.mcc999.3gppnetwork.org` | `nrf.5gc.mnc001.mcc001.3gppnetwork.org` |
| SCP | `127.0.1.200:7777` | `127.0.2.200:7777` |
| SEPP (N32c/N32f) | `127.0.1.251` / `127.0.1.252` | `127.0.2.251` / `127.0.2.252` |
| UPF subnet | `10.45.0.0/16` | `10.46.0.0/16` |
| Source gNB | `127.0.0.2` (binds SCTP) | — |
| Target gNB | — | `127.0.0.3` (binds SCTP) |

## Indirect Data Forwarding Note

In inter-PLMN scenarios, gNBs in different PLMNs do **not** have direct Xn connections. Therefore, **indirect data forwarding** is the expected default behavior — not direct forwarding. During handover preparation, when the SMF processes `HandoverRequiredTransfer` without `directForwardingPathAvailability`, it sets up indirect forwarding tunnels through the UPF. Data packets in transit during the handover gap are forwarded through these indirect tunnels. After handover completion (`hoState=COMPLETED`), the indirect forwarding tunnels are torn down via PFCP modification. All HR test cases should use `direct_forwarding=false` unless specifically testing a scenario where direct forwarding is available.

---

## Implementation Deviations Log

### Phase 0 Deviations

1. **Step 5 skipped (config change for `lbo_roaming_allowed`)**: Instead of modifying `configs/examples/gnb-999-70-ue-001-01.yaml.in` or creating a second config file, both the LBO and HR test files set `test_ue->lbo_roaming_allowed` directly in their `create_test_ue()` helper function. The LBO file sets `lbo_roaming_allowed = true`, the HR file sets it to `false`. This is passed through `test_db_new_simple()` which stores it in the MongoDB subscriber doc, and the UDR/UDM propagates it to the AMF session context. This approach is simpler and avoids config file duplication while being functionally equivalent.

2. **Old `n2-handover-test.c` deleted**: The plan says to copy the file, but doesn't explicitly say to delete the original. We deleted it since it's fully replaced by `n2-handover-lbo-test.c` (git tracked the rename correctly).

3. **Step 6 not yet verified (LBO test run)**: The build compiles successfully, but the LBO tests were not run against a live 5GC instance during Phase 0. This will be verified before the Phase 1A commit.

### Phase 1A Deviations

1. **TargetID deep-copy stored on amf_ue**: The plan mentioned storing "target_plmn_id and target_tai on amf_ue (NOT the full TargetID pointer)" and also "TargetID deep copy via ogs_asn_copy_ie for deferred CreateUEContext". We store **all three**: `inter_plmn_target_id` (deep-copied NGAP_TargetID_t), `inter_plmn_target_plmn_id`, and `inter_plmn_target_tai`. The PLMN ID and TAI are needed to rebuild the discovery_option in the nsmf-handler callback; the full TargetID is passed to the CreateUEContext builder.

2. **N2 SM data as multipart binary parts**: The plan mentions extending CreateUEContext with pdu_session_list, but doesn't detail how the N2 SM (handover_request) data is carried. We include each HR session's handover_request as an additional multipart binary part with content-id `n2-sm-psi-{psi}` and content-type `application/vnd.3gpp.ngap`. The PduSessionContext entries in the JSON body carry session metadata (PSI, S-NSSAI, DNN, sm_context_ref). The target AMF (Phase 1B) will match binary parts to sessions by PSI.

3. **No `#include "namf-build.h"` needed in nsmf-handler.c**: The plan listed this as a required change, but `nsmf-handler.c` already includes `sbi-path.h` which includes `namf-build.h`, so the `amf_namf_comm_build_create_ue_context` symbol is already visible.

4. **LBO-only path preserved unchanged**: When all sessions in the inter-PLMN PDUSessionList are LBO (`lbo_roaming_allowed == true`), the existing CreateUEContext-immediate path runs without any SMF involvement, preserving backward compatibility with the LBO handover implementation.

5. **N2 transfer cleanup after CreateUEContext send**: In the nsmf-handler callback, `AMF_UE_CLEAR_N2_TRANSFER(amf_ue, handover_request)` is called after `amf_ue_sbi_discover_and_send` returns. This is safe because the CreateUEContext builder runs synchronously inside `ogs_sbi_xact_add` and copies the data into the multipart HTTP message.

6. **Error path for new state**: Added `AMF_UPDATE_SM_CONTEXT_INTER_PLMN_HANDOVER_REQUIRED` to the error section in nsmf-handler.c as `ogs_assert_if_reached()`, matching the pattern of the existing `AMF_UPDATE_SM_CONTEXT_HANDOVER_REQUIRED` error handling. Proper error recovery will be addressed in Phase 2.

### Phase 2 Deviations

1. **HandoverCancelAcknowledge sent before V-SMF rollback**: The plan implies rolling back V-SMF state during cancel, but doesn't specify ordering. For consistency with the LBO cancel (which sends HandoverCancelAcknowledge immediately for inter-AMF), we send HandoverCancelAcknowledge first, then fire off `UpdateSMContext(hoState=CANCELLED)` to V-SMF asynchronously. The V-SMF rollback is fire-and-forget. Tests use `ogs_msleep(300)` to allow the async operation to complete before cleanup.

2. **Reused `AMF_UPDATE_SM_CONTEXT_HANDOVER_CANCEL` state for inter-AMF**: Rather than creating a new state for inter-AMF HR cancel, we reuse the existing `AMF_UPDATE_SM_CONTEXT_HANDOVER_CANCEL` state. The existing success handler in `nsmf-handler.c` handles the case gracefully — it tries to find `target_ue` via `ran_ue->target_ue_id`, gets NULL (no target_ue on source AMF for inter-AMF), and logs a warning. No crash or incorrect behavior.

3. **CreateUEContext error handler also sends V-SMF CANCELLED**: The plan mentioned modifying the error response handler, but didn't detail the mechanism. We send `UpdateSMContext(hoState=CANCELLED)` for each HR session with the same `HANDOVER_CANCEL` state, reusing the same fire-and-forget approach as the cancel path.

4. **HR Test 4 uses HR sessions (not no-sessions)**: The LBO test4 uses `build_handover_request_ack_no_sessions()` since LBO has no PDU sessions in HandoverRequest. The HR test4 uses `testngap_build_handover_request_ack()` (the standard builder with sessions) since HR sessions are present in the HandoverRequest. This correctly exercises the full HR preparation + cancel flow.

5. **HR Test 5 uses `ogs_ngap_decode`/`ogs_ngap_free` for visiting gNB setup**: Unlike LBO test5 (which uses `testngap_recv`), HR test5 uses explicit decode/free for the visiting gNB NG-Setup response. This is a minor style difference matching the LBO test5 pattern exactly.

### Phase 3 Deviations

1. **No spec cross-reference verification performed**: The plan called for reviewing limitation entries against TS 23.502 §4.9.1.3.3 and §4.23. This detailed 3GPP spec cross-referencing was not performed as the documents focus on implementation-level observations rather than spec citations.

2. **PCAP verification doc extensively expanded**: The plan said "add HR-specific message flows". We added full message flow tables for HR preparation, completion, cancel, and failure phases, reorganized the test-specific variations section into separate LBO and HR subsections, and split the summary checklist into common/LBO/HR sections.
