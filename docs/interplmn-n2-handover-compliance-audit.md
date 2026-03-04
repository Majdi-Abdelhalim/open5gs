### Phase 1 Audit Results — Preparation Phase HR

**Audit Date**: Completed  
**Spec References**: TS 23.502 §4.9.1.3.2 + §4.23.7.3.2

| Spec Step | Status | Implementation | Notes |
|-----------|--------|----------------|-------|
| §4.9.1.3.2 Step 1 (HandoverRequired) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L3309) | Extracts TargetID, PDUSessionList, SourceToTarget container, HandoverType, Cause. Validates all required IEs. Detects inter-PLMN by checking target PLMN against served GUAMIs. For V-SMF insertion: stores gNB HandoverRequiredTransfer. |
| §4.9.1.3.2 Step 2 (T-AMF Selection) | ✅ PASS | SBI discovery with target_plmn + target_tai | Uses NRF/SEPP discovery with `OGS_SBI_SERVICE_TYPE_NAMF_COMM` |
| §4.9.1.3.2 Step 3 (CreateUEContext) | ✅ PASS | [namf-build.c](src/amf/namf-build.c#L108) | Includes SUPI, PEI, SeafData (KAMF, ngKSI, NH, NCC), UE AMBR, 5GMM Capability, MmContextList, SourceToTarget container, NgapCause, ServingNetwork, N2 Notify URI, TargetID. V-SMF insertion path adds PduSessionContext with H-SMF URI. |
| §4.23.7.3.2 Step 2 (V-SMF Selection) | ✅ PASS | [namf-handler.c](src/amf/namf-handler.c#L2449) | T-AMF discovers V-SMF via `amf_sess_sbi_discover_and_send(NSMF_PDUSESSION)` |
| §4.23.7.3.2 Step 3 (CreateSMContext PREPARING) | ✅ PASS | [namf-handler.c](src/amf/namf-handler.c#L2465) | Sends with hoState=PREPARING, passes H-SMF URI from CreateUEContext |
| §4.23.7.3.2 Step 5 (Context Retrieval) | ⚠️ SIMPLIFIED | [nsmf-handler.c](src/smf/nsmf-handler.c#L498) | Uses Create(HO Prep) to H-SMF instead of separate PduSession_Context retrieval. H-SMF returns full context in 201 response. Valid simplification. |
| §4.23.7.3.2 Step 6 (V-UPF Selection) | ✅ PASS | [nsmf-handler.c](src/smf/nsmf-handler.c#L523) | `smf_sess_select_upf()` + association check |
| §4.23.7.3.2 Step 7a-b (V-UPF N4 Establishment) | ✅ PASS | [nsmf-handler.c](src/smf/nsmf-handler.c#L556) → [gsm-sm.c](src/smf/gsm-sm.c#L812) | N4 established with default QoS (QFI=1, 5QI=9). V-UPF F-TEID obtained for H-SMF Create. UL FAR to H-UPF not set yet (chicken-and-egg — set after H-SMF 201). |
| §4.23.7.3.2 Step 7c-f (V-SMF → H-SMF Create) | ✅ PASS | [gsm-sm.c](src/smf/gsm-sm.c#L820) → [nsmf-handler.c](src/smf/nsmf-handler.c#L1800) | V-SMF sends Create with ho_preparation_indication. H-SMF stores vcnTunnelInfo in `sess->handover.*` (Fix #3 staging). H-SMF returns 201 with hcnTunnelInfo (H-UPF N9 F-TEID), UE IP, QoS, sessionAmbr. |
| §4.23.7.3.2 Step 8 (V-SMF 201 to T-AMF) | ✅ PASS | [sbi-path.c](src/smf/sbi-path.c#L359) | Builds PDUSessionResourceSetupRequestTransfer with V-UPF N3 F-TEID. Sends deferred 201 with N2 SM. T-AMF stores as `sess->transfer.handover_request`. |
| §4.9.1.3.2 Step 8 (AMF supervises) | ⚠️ DEVIATION | [nsmf-handler.c](src/amf/nsmf-handler.c#L193) | Uses `AMF_SESSION_SYNC_DONE()` — no max delay timer. If V-SMF doesn't respond, AMF waits indefinitely. |
| §4.9.1.3.2 Step 9 (HandoverRequest) | ✅ PASS | [ngap-build.c](src/amf/ngap-build.c#L2146) | Includes AMF_UE_NGAP_ID, HandoverType, Cause, UEAggregateMaxBitRate, UESecurityCapabilities, SecurityContext (NH/NCC), PDUSessionResourceSetupListHOReq, AllowedNSSAI, MaskedIMEISV, SourceToTarget container, GUAMI. |
| §4.9.1.3.2 Step 10 (HandoverRequestAck) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L3802) | Extracts PDUSessionResourceAdmittedList + TargetToSource container. For inter-AMF: sends UpdateSMContext(PREPARED) to V-SMF per session. |
| §4.23.7.3.2 Step 15 (UpdateSMContext PREPARED) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L3960) | Passes HandoverRequestAcknowledgeTransfer to V-SMF with hoState=PREPARED |
| §4.23.7.3.2 Step 16a-b (V-UPF N4 Modification) | ⚠️ DEFERRED | [ngap-handler.c](src/smf/ngap-handler.c#L826) | V-SMF does NOT modify V-UPF during preparation. Stores target gNB N3 info in `sess->handover.*` and sets `dl_far->handover.prepared = true`. Actual DL FAR update happens in COMPLETED phase. Valid per spec (step 16a is [Conditional]). |
| §4.23.7.3.2 Step 23 (V-SMF → T-AMF PREPARED response) | ✅ PASS | [ngap-handler.c](src/smf/ngap-handler.c#L935) | Sends HandoverCommandTransfer with hoState=PREPARED |
| §4.9.1.3.2 Step 12 (CreateUEContext Response) | ✅ PASS | [nsmf-handler.c](src/amf/nsmf-handler.c#L649) | When all V-SMF responses received: builds 201 with TargetToSource container + per-session HandoverCommandTransfer as multipart. Sends on deferred stream. |

**Summary**: No bugs found in preparation phase. Implementation follows spec correctly with minor
simplifications (context retrieval bundled into Create, no max delay timer, V-UPF N4 mod deferred to
execution phase). All tested HR tests pass.

**Missing Optional IEs** (not critical for test scope):
- UE Radio Capability ID (TS 38.413)
- Tracing Requirements
- Service area restrictions
- LTE M Indication

### Phase 2 Audit Results — Execution Phase HR

**Audit Date**: Completed  
**Spec References**: TS 23.502 §4.9.1.3.3 + §4.23.7.3.3

| Spec Step | Status | Implementation | Notes |
|-----------|--------|----------------|-------|
| §4.9.1.3.3 Step 1 (HandoverCommand) | ✅ PASS | [ngap-build.c](src/amf/ngap-build.c#L2538) | Includes AMF/RAN_UE_NGAP_ID, HandoverType, PDUSessionResourceHandoverList (per-session handoverCommandTransfer), TargetToSource_TransparentContainer. |
| §4.9.1.3.3 Steps 2a-2c (RANStatusTransfer) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4591) → [namf-handler.c](src/amf/namf-handler.c#L2856) | S-AMF detects inter-AMF HR (ue_at_home + has_hr_sessions), APER-encodes RANStatusTransfer_TransparentContainer, sends N2InfoNotify(RAN_STATUS) to T-AMF. T-AMF decodes binary part and sends DownlinkRANStatusTransfer to target gNB. LBO: skips forwarding. |
| §4.9.1.3.3 Step 5 (HandoverNotify) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4927) | T-AMF associates UE with target ran_ue, updates TAI/CGI. For inter-AMF: sends N2InfoNotify(COMPLETED) + UpdateSMContext(COMPLETED) per HR session. |
| §4.9.1.3.3 Step 6a (N2InfoNotify COMPLETED) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4948) | T-AMF calls `amf_sbi_send_n2_info_notify(amf_ue)` for HANDOVER_COMPLETED. |
| §4.9.1.3.3 Step 6b (N2InfoNotify ACK) | ⚠️ IMPLICIT | [namf-handler.c](src/amf/namf-handler.c#L2916) | S-AMF returns 200 OK (ogs_sbi_server_send_response). No explicit Secondary RAT usage data in ACK. |
| §4.23.7.3.3 Step 2 (UpdateSMContext COMPLETED → V-SMF) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4960) | T-AMF iterates HR sessions, sends hoState=COMPLETED to V-SMF with `AMF_UPDATE_SM_CONTEXT_INTER_PLMN_HANDOVER_COMPLETED_AT_TARGET`. |
| §4.23.7.3.3 Steps 5a-b (V-UPF N4 Modification) | ✅ PASS | [nsmf-handler.c](src/smf/nsmf-handler.c#L1042) | V-SMF applies staged handover data → DL FAR to target gNB N3. pfcp_flags includes DL_ONLY\|ACTIVATE\|N2_HANDOVER\|HOME_ROUTED_ROAMING\|UL_ONLY\|OUTER_HEADER_REMOVAL (Fix #4). No end markers (had_active_dl=false for fresh V-UPF). |
| §4.23.7.3.3 Step 6 (V-SMF → H-SMF Update) | ✅ PASS | [n4-handler.c](src/smf/n4-handler.c#L413) | After V-UPF PFCP response: sends HsmfUpdateData with vcnTunnelInfo (V-UPF DL N9 F-TEID), up_cnx_state=ACTIVATED, state=ACTIVATED_FROM_N2_HANDOVER. |
| §4.23.7.3.3 Steps 7a-b (H-UPF N4 Modification) | ✅ PASS | [gsm-sm.c](src/smf/gsm-sm.c#L1240) | H-SMF parses vcnTunnelInfo, applies staged sess->handover.* data (Fix #3), sets H-UPF DL FAR → V-UPF N9, sends PFCP mod with DL_ONLY\|ACTIVATE\|HOME_ROUTED_ROAMING. |
| §4.23.7.3.3 Step 8 (H-SMF → V-SMF Response) | ✅ PASS | [n4-handler.c](src/smf/n4-handler.c#L530) | H-SMF sends 204 no_content after H-UPF PFCP success (HOME_ROUTED_ROAMING_IN_HSMF + DL_ONLY path). |
| §4.23.7.3.3 Step 9 (V-SMF → T-AMF Response) | ✅ PASS | [gsm-sm.c](src/smf/gsm-sm.c#L1738) | V-SMF receives H-SMF 204, handles indirect forwarding cleanup, sends smf_sbi_send_sm_context_updated_data_ho_state(COMPLETED) to T-AMF. |
| §4.9.1.3.3 Step 7 (S-AMF UpdateSMContext COMPLETED) | ✅ PASS | [namf-handler.c](src/amf/namf-handler.c#L2961) | For V-SMF insertion (ue_at_home): S-AMF clears SM context (CLEAR_SESSION_CONTEXT) — V-SMF now manages H-SMF lifecycle. No release sent to H-SMF. |
| §4.9.1.3.3 Step 11 (SMF confirms) | ✅ PASS | [nsmf-handler.c](src/amf/nsmf-handler.c#L1108) | T-AMF receives V-SMF COMPLETED response, logs data path switched. |
| §4.9.1.3.3 Step 12 (Registration) | ⚠️ N/A | — | Mobility Registration Update is a separate procedure; not exercised in test scope. |
| §4.9.1.3.3 Steps 13-14 (UEContextRelease) | ✅ PASS | [namf-handler.c](src/amf/namf-handler.c#L2928) | S-AMF sends UEContextReleaseCommand(successful_handover) to source gNB after N2InfoNotify(COMPLETED) received from T-AMF. |
| §4.23.7.3.3 Step 3a (Source I-SMF Release) | ⚠️ N/A | — | V-SMF insertion scenario has no source I-SMF. S-AMF does CLEAR_SESSION_CONTEXT instead. |

**Summary**: No bugs found in execution phase. The full chain is verified:
T-AMF → V-SMF(COMPLETED) → V-UPF PFCP mod → V-SMF → H-SMF(HsmfUpdate) → H-UPF PFCP mod → H-SMF(204) → V-SMF(200 COMPLETED) → T-AMF.
S-AMF handles differently: N2InfoNotify(COMPLETED) → UEContextRelease + CLEAR_SESSION_CONTEXT for V-SMF insertion.
Data path: DN → PSA-UPF → (N9) → V-UPF → (N3) → target gNB ✓

**Key Implementation Details**:
- V-UPF PFCP mod includes both DL_ONLY and UL_ONLY (Fix #4) — UL FAR to H-UPF was not set during establishment
- H-SMF applies staged handover data from sess->handover.* (Fix #3) before comparing with vcnTunnelInfo
- No end markers sent by V-UPF (had_active_dl=false) — correct for freshly-inserted UPF
- S-AMF V-SMF insertion path: clears SM context rather than releasing H-SMF session

### Phase 3 Audit Results — Preparation Phase LBO

**Audit Date**: Completed  
**Spec References**: TS 23.502 §4.9.1.3.2 (LBO inter-PLMN subset)

| Spec Step | Status | Implementation | Notes |
|-----------|--------|----------------|-------|
| §4.9.1.3.2 Step 1 (HandoverRequired) | ✅ PASS | Same as HR | S-AMF detects inter-PLMN, stores HandoverRequiredTransfer per session. LBO sessions have `lbo_roaming_allowed=true`. |
| §4.9.1.3.2 Step 3 (CreateUEContext) | ✅ PASS | [namf-build.c](src/amf/namf-build.c#L300) | LBO sessions excluded from both V-SMF insertion path (`!sess->lbo_roaming_allowed` check) and old HR path. CreateUEContext contains only UE context (SUPI, security, NH/NCC) — no PDU session info. |
| §4.9.1.3.2 Step 3 (T-AMF receives) | ✅ PASS | [namf-handler.c](src/amf/namf-handler.c#L2485) | No `session_context_list` and no `pdu_session_list` → T-AMF takes "LBO" branch, sends HandoverRequest directly to target gNB. No V-SMF contacted. |
| §4.9.1.3.2 Step 9 (HandoverRequest) | ✅ PASS | [ngap-build.c](src/amf/ngap-build.c#L2350) | T-AMF has no sessions → PDUSessionResourceSetupListHOReq is empty. HandoverRequest still includes security context, UE AMBR, SourceToTarget container. |
| §4.9.1.3.2 Step 10 (HandoverRequestAck) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4010) | No PDUSessionResourceAdmittedList. LBO test uses `build_handover_request_ack_no_sessions()`. |
| §4.9.1.3.2 Step 12 (CreateUEContext 201) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4018) | No PDU sessions → responds immediately with TargetToSource container + empty pdu_session_list (no V-SMF to wait for). |

**Summary**: LBO sessions are correctly excluded from inter-PLMN handover preparation. The `lbo_roaming_allowed` flag prevents them from being included in CreateUEContext. The T-AMF sends HandoverRequest without PDU sessions, and responds immediately with CreateUEContext 201 since there's no V-SMF interaction needed. Sessions will be released at S-AMF and re-established at V-AMF post-handover.

### Phase 4 Audit Results — Execution Phase LBO

**Audit Date**: Completed  
**Spec References**: TS 23.502 §4.9.1.3.3 (LBO subset)

| Spec Step | Status | Implementation | Notes |
|-----------|--------|----------------|-------|
| §4.9.1.3.3 Step 1 (HandoverCommand) | ✅ PASS | [ngap-build.c](src/amf/ngap-build.c#L2538) | Same as HR. PDUSessionResourceHandoverList empty for LBO (no sessions have handoverCommandTransfer). |
| §4.9.1.3.3 Steps 2a-2c (RANStatusTransfer) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4697) | S-AMF skips forwarding for LBO: `has_hr_sessions=false` → "Inter-AMF LBO handover: skip RANStatusTransfer forwarding". Correct since no DRBs are preserved. |
| §4.9.1.3.3 Step 5 (HandoverNotify) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4927) | T-AMF associates UE with target ran_ue, sends N2InfoNotify(COMPLETED) to S-AMF. No UpdateSMContext since no sessions exist at T-AMF for LBO. |
| §4.9.1.3.3 Step 6a (N2InfoNotify COMPLETED) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4948) | Same as HR. |
| §4.9.1.3.3 Steps 6b-6c (S-AMF session release) | ✅ PASS | [namf-handler.c](src/amf/namf-handler.c#L2990) | LBO sessions hit `else` path: `amf_sbi_send_release_session()` releases SM context at source SMF directly. |
| §4.9.1.3.3 Steps 13-14 (UEContextRelease) | ✅ PASS | [namf-handler.c](src/amf/namf-handler.c#L2928) | S-AMF sends UEContextReleaseCommand(successful_handover) to source gNB. |
| Post-HO (New PDU session) | ✅ PASS | LBO test Phase 3 | Test establishes new PDU session (PSI 7) at visiting AMF, verifies GTP-U data path via `verify_gtpu_post_handover()`. |

**Summary**: LBO execution correctly handles session lifecycle: old sessions released at S-AMF, UEContextRelease to source gNB, new sessions established at visiting AMF. No PFCP or SMF operations during handover (sessions are released+re-established, not migrated). RANStatusTransfer correctly skipped (no DRBs to preserve).

### Phase 5 Audit Results — Cancel/Failure Paths

**Audit Date**: Completed  
**Spec References**: TS 23.502 §4.9.1.3.4 (Cancellation)

| Scenario | Status | Implementation | Notes |
|----------|--------|----------------|-------|
| HR Cancel (test4) — S-AMF path | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4470) | S-AMF detects `inter_amf_handover`, sends HandoverCancelAcknowledge immediately (no target_ue on source AMF). Iterates HR sessions, sends UpdateSMContext(CANCELLED) to V-SMF with NGAP cause. Clears `inter_amf_handover`. |
| HR Cancel — V-SMF CANCELLED | ✅ PASS | [nsmf-handler.c](src/smf/nsmf-handler.c#L1145) | Clears `sess->handover.prepared` on all QoS flows. For H-SMF: clears `vsmf_pdu_session_uri` and `v_smf.client`, reverting to non-roaming mode. Removes indirect forwarding if any. |
| HR Cancel — T-AMF cleanup | ⚠️ TIMEOUT | — | No explicit cancel notification to visiting AMF. T-AMF UE context + V-UPF cleanup relies on implicit timeout. Acceptable for test scope. |
| HR Failure (test5) — T-AMF path | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4291) | T-AMF sends 403 on deferred CreateUEContext stream. Releases all V-SMF sessions with `AMF_RELEASE_SM_CONTEXT_INTER_PLMN_HANDOVER_FAILURE`. Removes target ran_ue. `amf_ue_remove()` deferred until all releases complete via `AMF_SESSION_SYNC_DONE`. |
| HR Failure — S-AMF path | ✅ PASS | [namf-handler.c](src/amf/namf-handler.c#L2510) | On CreateUEContext error: sends HandoverPreparationFailure to source gNB. For V-SMF insertion (UE at home): correctly skips UpdateSMContext(CANCELLED) since no SMF was contacted at source. |
| LBO Cancel (test4) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4489) | Same inter-AMF cancel branch. No HR sessions → no V-SMF notification needed. HandoverCancelAcknowledge sent immediately. |
| LBO Failure (test5) | ✅ PASS | [ngap-handler.c](src/amf/ngap-handler.c#L4318) | T-AMF sends 403, no sessions to release (empty sess_list for LBO), `amf_ue_remove()` called immediately. S-AMF receives HandoverPreparationFailure. |
| V-SMF Release on Failure | ✅ PASS | [nsmf-handler.c](src/amf/nsmf-handler.c#L1628) | Async completion handler removes `amf_ue` when all session releases complete. |

**Summary**: Cancel and failure paths work correctly for both HR and LBO scenarios. HR cancel properly rolls back V-SMF state and H-SMF session reference. HR failure properly releases V-SMF sessions with sync tracking. The only gap is that cancel doesn't explicitly notify the T-AMF — it relies on implicit timeout for target-side cleanup. All tests (4 and 5) pass for both HR and LBO.