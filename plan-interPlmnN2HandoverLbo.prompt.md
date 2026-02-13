## Plan: Inter-PLMN N2 Handover (LBO, Release-and-Reestablish)

**TL;DR**: Implement Namf_Communication_CreateUEContext and N2InfoNotify to enable N2-based inter-PLMN handover between a Home AMF (999-70) and a Visiting AMF (001-01). For local breakout, PDU sessions are *not* transferred during the handover — only UE context (security, registration) is moved. After handover completes, old sessions are released at the source SMF, and the UE re-establishes new LBO sessions in the visited PLMN. This leverages existing SEPP inter-PLMN routing, all existing OpenAPI models (`UeContextCreateData`, `N2InformationNotification`, etc.), and the existing intra-PLMN handover mechanics on the target AMF side.

**Steps**

### Step 1: Library — Add SBI resource name constants and state definitions

In [lib/sbi/message.h](lib/sbi/message.h), add resource name constants alongside the existing `OGS_SBI_RESOURCE_NAME_TRANSFER`:
- `OGS_SBI_RESOURCE_NAME_N2_INFO_NOTIFY` (for the N2InfoNotify callback path)

In [src/amf/sbi-path.h](src/amf/sbi-path.h), add new handover state constants alongside the existing `AMF_UPDATE_SM_CONTEXT_HANDOVER_*` values:
- `AMF_NAMF_COMM_CREATE_UE_CONTEXT` — state for the source AMF's outgoing CreateUEContext SBI transaction
- `AMF_NAMF_COMM_N2_INFO_NOTIFY` — state for incoming N2InfoNotify

### Step 2: AMF context — Add inter-AMF handover fields

In [src/amf/context.h](src/amf/context.h), extend `amf_ue_t`:
- `bool inter_amf_handover` — flag indicating this handover crosses AMF boundaries
- `char *n2_notify_uri` — callback URI the source AMF provides in CreateUEContext; target AMF stores it and calls it on handover completion
- `ogs_pool_id_t create_ue_context_stream_id` — on the target AMF side, stores the deferred SBI server stream for the CreateUEContext request (using the `ogs_sbi_id_from_stream()` / `ogs_sbi_stream_find_by_id()` pattern from [SMF deferred responses](src/smf/sbi-path.c#L218))
- `ogs_pool_id_t source_amf_ue_id` — on the target AMF, tracks the pool ID reference for the original UE context (for linking the CreateUEContext flow to the NGAP handover state)

In [src/amf/context.c](src/amf/context.c), initialize/free these fields in `amf_ue_add()` / `amf_ue_remove()`.

### Step 3: Source AMF — Detect inter-PLMN and discover target AMF

Modify `ngap_handle_handover_required()` in [src/amf/ngap-handler.c](src/amf/ngap-handler.c#L3309-L3343). At the existing inter-PLMN detection point, instead of sending ErrorIndication:

1. Set `amf_ue->inter_amf_handover = true`
2. Store the handover context (type, cause, NH/NCC, SourceToTarget container) — this already happens in the existing flow
3. Build `ogs_sbi_discovery_option_t` with:
   - `ogs_sbi_discovery_option_add_target_plmn_list(discovery_option, &target_plmn_id)` — routes via SEPP to the target PLMN
   - `ogs_sbi_discovery_option_set_tai(discovery_option, &target_tai)` — target TAI for precise AMF selection (using the existing AMF NF profile TAI list registered at [nnrf-build.c](lib/sbi/nnrf-build.c#L919))
4. Call `amf_ue_sbi_discover_and_send()` with `OGS_SBI_SERVICE_TYPE_NAMF_COMM`, the CreateUEContext builder (Step 4), and state `AMF_NAMF_COMM_CREATE_UE_CONTEXT`
5. Return (handover continues asynchronously via SBI)

The existing `amf_ue_sbi_discover_and_send()` at [src/amf/sbi-path.c](src/amf/sbi-path.c#L97) needs modification: currently it only adds `target_plmn_list` for AUSF/UDM. Extend the condition to also handle `OGS_SBI_SERVICE_TYPE_NAMF_COMM` when the discovery_option already has target_plmn_list set (i.e., respect caller-provided target PLMN).

**Important**: Do NOT iterate PDU sessions for SMF UpdateSMContext (the `HANDOVER_REQUIRED` SMF notification at [lines 3504-3519](src/amf/ngap-handler.c#L3504-L3519)) — skip this for inter-AMF handover since sessions are not being transferred.

### Step 4: Source AMF — Build CreateUEContext request

Add `amf_namf_comm_build_create_ue_context()` in [src/amf/namf-build.c](src/amf/namf-build.c):

The function builds a POST request to `/namf-comm/v1/ue-contexts/{supi}` (the CreateUEContext endpoint is a PUT or POST to the ue-contexts collection).

Populate `OpenAPI_ue_context_create_data_t` (model already exists at [ue_context_create_data.h](lib/sbi/openapi/model/ue_context_create_data.h)):
- `ue_context` → `OpenAPI_ue_context_t`:
  - `supi` from `amf_ue->supi`
  - `pei` from `amf_ue->pei`
  - `sub_ue_ambr` (UE AMBR)
  - `seaf_data` (KAMF, ngKSI) — reuse the serialization logic from existing `amf_namf_comm_handle_ue_context_transfer_request()` at [namf-handler.c](src/amf/namf-handler.c#L1427-L1465)
  - `_5g_mm_capability` (base64-encoded)
  - `mm_context_list` (NAS security mode, NAS counts, UE security capability, allowed NSSAI) — reuse logic from [namf-handler.c](src/amf/namf-handler.c#L1508-L1599)
  - `session_context_list` — include PDU session references (PSI, sm_context_ref, S-NSSAI, DNN) for informational purposes, even though they won't be actively transferred
- `target_id` → `OpenAPI_ng_ran_target_id_t`:
  - `ran_node_id` with target gNB ID and PLMN
  - `tai` with target TAI
- `source_to_target_data` → `OpenAPI_n2_info_content_t`:
  - `ngap_ie_type` = `SRC_TO_TAR_CONTAINER`
  - `ngap_data` = SourceToTarget_TransparentContainer from `amf_ue->handover.container`
- `n2_notify_uri` — the source AMF's callback URI for receiving handover completion notification (construct from AMF's own SBI address + a unique path like `/namf-comm/v1/ue-contexts/{supi}/n2-info-notify`)
- `serving_network` → source AMF's PLMN
- `ngap_cause` → handover cause

Also include: UE security capabilities, NH/NCC in the UeContext's MM context, and the `amf_ue->handover.type`.

### Step 5: Target AMF — Server handler for CreateUEContext

Add a new route in the SBI server dispatcher at [src/amf/amf-sm.c](src/amf/amf-sm.c#L193-L250):

Under `CASE(OGS_SBI_SERVICE_NAME_NAMF_COMM)` → `CASE(OGS_SBI_RESOURCE_NAME_UE_CONTEXTS)`, add routing for POST/PUT to ue-contexts collection (distinguish from the existing `transfer` and `transfer-update` sub-resources by checking the HTTP method and path depth — CreateUEContext is POST to `ue-contexts/{ueContextId}` without a trailing sub-resource like `/transfer`).

Add `amf_namf_comm_handle_create_ue_context_request()` in [src/amf/namf-handler.c](src/amf/namf-handler.c):

1. Parse `UeContextCreateData` from the request body (multipart: JSON + binary N2 data)
2. Create a new `amf_ue_t` on the target AMF:
   - Set `supi`, `pei`, security context (KAMF, NH, NCC, ngKSI)
   - Set UE security capabilities, NAS security mode, NAS counts
   - Set allowed NSSAI
   - Set `amf_ue->inter_amf_handover = true`
   - Store `n2_notify_uri` from the request
3. Extract `target_id` → find local target gNB via `amf_gnb_find_by_gnb_id(target_gnb_id)` — this gNB is connected to THIS (target) AMF
4. If gNB not found → respond with 403 `UeContextCreateError`
5. Create `ran_ue` via `ran_ue_add(target_gnb, INVALID_UE_NGAP_ID)` — the target RAN UE
6. Associate: `amf_ue_associate_ran_ue(amf_ue, target_ue)` (no source_ue on this AMF — the target AMF's ran_ue IS the target_ue directly)
7. Store the SourceToTarget_TransparentContainer in `amf_ue->handover.container`
8. Store the handover type, cause
9. **Defer SBI response**: Store the SBI stream via `amf_ue->create_ue_context_stream_id = ogs_sbi_id_from_stream(stream)`
10. Compute NH/NCC: `amf_ue->nhcc++`, `ogs_kdf_nh_gnb(amf_ue->kamf, amf_ue->nh, amf_ue->nh)`
11. Send `ngap_send_handover_request(amf_ue)` to the target gNB — this reuses the existing `ngap_build_handover_request()` at [ngap-build.c](src/amf/ngap-build.c#L2147), which will build HandoverRequest with an **empty** PDUSessionResourceSetupListHOReq (since no sessions have `transfer.handover_request` set)

### Step 6: Target AMF — Modify HandoverRequestAck to send CreateUEContext response

Modify `ngap_handle_handover_request_ack()` at [src/amf/ngap-handler.c](src/amf/ngap-handler.c#L3528-L3767):

After parsing the HandoverRequestAck (receiving TargetToSource_TransparentContainer):

- **Check** `amf_ue->inter_amf_handover == true`:
  - If true (inter-AMF case):
    1. Store `TargetToSource_TransparentContainer` in `amf_ue->handover.container`
    2. Recover the deferred SBI stream: `stream = ogs_sbi_stream_find_by_id(amf_ue->create_ue_context_stream_id)`
    3. Build `UeContextCreatedData` response:
       - `ue_context` — the created UE context on target AMF
       - `target_to_source_data` → `N2InfoContent` with the TargetToSource_TransparentContainer
       - `pdu_session_list` — empty (no sessions transferred)
       - `failed_session_list` — list all sessions from the request (all failed due to LBO release-and-reestablish)
    4. Send HTTP 201 Created response on the recovered stream
    5. **Do NOT** send UpdateSMContext to any SMFs (no session transfer)
    6. Return
  - If false (intra-PLMN case): proceed with existing flow (send UpdateSMContext per session, then HandoverCommand via nsmf-handler sync)

Similarly, modify `ngap_handle_handover_failure()` at [src/amf/ngap-handler.c](src/amf/ngap-handler.c#L3756):
- If `amf_ue->inter_amf_handover`: recover stream and send CreateUEContext error response (403 or 500)

### Step 7: Source AMF — Handle CreateUEContext response → send HandoverCommand

Add client-side response routing in [src/amf/amf-sm.c](src/amf/amf-sm.c#L487-L522) and the appropriate GMM state machine state (likely `gmm_state_registered()` at [src/amf/gmm-sm.c](src/amf/gmm-sm.c)):

Under `OGS_EVENT_SBI_CLIENT` → `CASE(OGS_SBI_SERVICE_NAME_NAMF_COMM)` → `CASE(OGS_SBI_RESOURCE_NAME_UE_CONTEXTS)`:
- Add a new case for CreateUEContext responses (differentiate from `transfer` responses by checking `xact->state == AMF_NAMF_COMM_CREATE_UE_CONTEXT`)

Add `amf_namf_comm_handle_create_ue_context_response()` in [src/amf/namf-handler.c](src/amf/namf-handler.c):

On HTTP 201 (success):
1. Parse `UeContextCreatedData`
2. Extract `target_to_source_data` → decode `TargetToSource_TransparentContainer`
3. Store in `amf_ue->handover.container` (overwriting the previous SourceToTarget)
4. Call `ngap_send_handover_command(amf_ue)` — sends HandoverCommand to source gNB (reuses existing [ngap_build_handover_command](src/amf/ngap-build.c#L2538) which reads `amf_ue->handover.container`; the PDUSessionResourceHandoverList will be empty since no sessions have `transfer.handover_command`)

On HTTP 403/error (failure):
1. Send `ngap_send_handover_preparation_failure()` to source gNB with appropriate cause
2. Clean up inter-AMF handover state

### Step 8: Source AMF — Handle RANStatusTransfer forwarding (simplified)

For the initial LBO implementation without PDU session transfer, UplinkRANStatusTransfer from the source gNB can be handled minimally:
- The existing `ngap_handle_uplink_ran_status_transfer()` sends DownlinkRANStatusTransfer to the target gNB
- For inter-AMF, this would need to be forwarded to the target AMF via N2InfoNotify
- **For the initial LBO implementation (no PDU sessions)**: skip RANStatusTransfer forwarding — there are no data radio bearers to transfer status for. Modify the handler to skip forwarding when `amf_ue->inter_amf_handover == true` and no sessions are being transferred.

### Step 9: Target AMF — Handle HandoverNotify → send N2InfoNotify

Modify `ngap_handle_handover_notify()` at [src/amf/ngap-handler.c](src/amf/ngap-handler.c#L4162-L4370):

After existing processing (update `amf_ue` location, associate with target ran_ue):

- **Check** `amf_ue->inter_amf_handover == true`:
  - If true:
    1. The target AMF is now the serving AMF for this UE
    2. Send `N2InfoNotify` to source AMF via `amf_ue->n2_notify_uri`:
       - Build `OpenAPI_n2_information_notification_t` with `notify_reason = HANDOVER_COMPLETED`
       - Send as HTTP POST to the stored `n2_notify_uri`
       - This is a direct SBI client call (not NRF-discovered — we have the exact URI)
    3. **Do NOT** send UpdateSMContext(COMPLETED) to any SMFs (no sessions on target AMF yet)
    4. Do not send UEContextReleaseCommand to source gNB (that's on a different AMF — the source AMF handles cleanup after receiving the N2InfoNotify)
  - If false: existing flow (UpdateSMContext per session, UEContextRelease to source gNB)

### Step 10: Source AMF — Handle N2InfoNotify callback → cleanup

Add server-side routing in [src/amf/amf-sm.c](src/amf/amf-sm.c) for the N2InfoNotify callback:

Under `CASE(OGS_SBI_SERVICE_NAME_NAMF_COMM)` → `CASE(OGS_SBI_RESOURCE_NAME_UE_CONTEXTS)` → add case for the `n2-info-notify` sub-resource.

Add `amf_namf_comm_handle_n2_info_notify()` in [src/amf/namf-handler.c](src/amf/namf-handler.c):

1. Parse `N2InformationNotification` — check `notify_reason == HANDOVER_COMPLETED`
2. Find the `amf_ue` from the URI path (SUPI)
3. Release old PDU sessions at the source SMF(s):
   - For each session in `amf_ue->sess_list`: send `Nsmf_PDUSession_ReleaseSMContext` to the source SMF
4. Release the source gNB UE context:
   - Find `source_ue` (the ran_ue associated with the source gNB)
   - Send `ngap_send_ran_ue_context_release_command(source_ue, NGAP_UE_CTX_REL_NG_HANDOVER_COMPLETE)`
5. Clean up the `amf_ue` on the source AMF (the UE is now served by the target AMF)
6. Respond with HTTP 200 OK

### Step 11: Build N2InfoNotify request function

Add `amf_namf_comm_build_n2_info_notify()` in [src/amf/namf-build.c](src/amf/namf-build.c):

Build an HTTP POST request to the source AMF's `n2_notify_uri` with:
- `OpenAPI_n2_information_notification_t`:
  - `n2_notify_subscription_id` — identifier
  - `notify_reason` = `OpenAPI_n2_info_notify_reason_HANDOVER_COMPLETED`
  - `guami` — target AMF's GUAMI (new serving GUAMI for the UE)

For direct SBI client call (not NRF-discovered), use `ogs_sbi_client_find_by_uri()` or create a new client from the `n2_notify_uri`, then `ogs_sbi_send_request_to_client()`. Note: if the source AMF is in a different PLMN, this call routes through SEPP automatically (the SBI framework checks FQDN PLMN).

### Step 12: Update test — expect successful handover

Modify [tests/roaming/n2-handover-test.c](tests/roaming/n2-handover-test.c):

Update `test1_func` to exercise the full inter-PLMN handover flow:

1. **Setup** (unchanged): Home gNB → Home AMF, Visiting gNB → Visiting AMF, UE registered in Home PLMN with PDU session
2. **HandoverRequired**: Send from source gNB to Home AMF (unchanged)
3. **Expect HandoverCommand** instead of ErrorIndication:
   - `recvbuf = testgnb_ngap_read(ngap_home)` — should now return HandoverCommand
   - Decode and verify `NGAP_NGAP_PDU_PR_successfulOutcome` with procedure code `id_HandoverPreparation`
   - Verify empty PDUSessionResourceHandoverList (no sessions transferred for LBO)
4. **Send HandoverNotify** from target gNB to Visiting AMF:
   - `sendbuf = testngap_build_handover_notify(test_ue)` (target gNB advertises new location)
   - `rv = testgnb_ngap_send(ngap_visiting, sendbuf)`
5. **Receive UEContextReleaseCommand** on source gNB (from Home AMF, after N2InfoNotify):
   - `recvbuf = testgnb_ngap_read(ngap_home)`
   - Send UEContextReleaseComplete back
6. **Verify**: UE is now served by Visiting AMF — can establish new LBO PDU session via `ngap_visiting`
7. **Cleanup**: Release UE context from Visiting AMF

Update `test2_func` and `test3_func` similarly, adapting for indirect forwarding and multiple sessions scenarios.

### Step 13: Handle error/cancellation paths

In [src/amf/ngap-handler.c](src/amf/ngap-handler.c):

**HandoverCancel (source AMF)**:  
Modify `ngap_handle_handover_cancel()` — add an inter-AMF branch **before** the `target_ue` lookup (line ~4170). In the inter-AMF case, the source AMF has NO `target_ue` (it was created on the visiting AMF via CreateUEContext). When `amf_ue->inter_amf_handover == true`:
1. Send `ngap_send_handover_cancel_ack(source_ue)` immediately (no SMF UpdateSMContext needed — for LBO, sessions were never transferred)
2. Clear `amf_ue->inter_amf_handover = false`
3. Return (skip the `target_ue` lookup and SMF cancellation iteration)
4. The visiting AMF's UE context will be cleaned up by timeout — no explicit cancel notification in this implementation.

**HandoverFailure (target AMF)**:  
Already implemented in Step 6 (line ~4008). When `amf_ue->inter_amf_handover`:
1. Sends 403 error on the deferred CreateUEContext stream
2. Removes amf_ue and ran_ue on the target AMF
3. Source AMF receives the error in `amf_namf_comm_handle_create_ue_context_response()` (Step 7) → sends `HandoverPreparationFailure` to source gNB

**Test cases** (in [tests/roaming/n2-handover-test.c](tests/roaming/n2-handover-test.c)):

- `test4_func` — **HandoverCancel**: Full setup → HandoverRequired → (visiting AMF: HandoverRequest → HandoverRequestAck) → HandoverCommand on source gNB → **HandoverCancel** from source gNB → expect **HandoverCancelAcknowledge** on source gNB. Verify the source AMF does not crash (no target_ue lookup). Visiting AMF continues. Cleanup via deregistration.

- `test5_func` — **HandoverFailure**: Full setup → HandoverRequired → (visiting AMF: HandoverRequest → **HandoverFailure** from target gNB) → expect **HandoverPreparationFailure** on source gNB. Verify the visiting AMF responds with 403 on the CreateUEContext stream. Cleanup via deregistration.

---

### Bug Fixes Discovered During Step 12 Testing

These bugs were found in previously committed code when the Step 12 test rewrite exercised the full inter-PLMN handover flow for the first time:

**Bug 1 (Step 6 — ngap-handler.c)**: `UeContextCreatedData.pdu_session_list` was NULL → `OpenAPI_ue_context_created_data_convertToJSON()` crashed with assertion failure on the visiting AMF.  
**Fix**: Added `UeContextCreatedData.pdu_session_list = OpenAPI_list_create();` before serialization and `OpenAPI_list_free()` after response sent.

**Bug 2 (Step 9+11 — namf-build.c)**: N2InfoNotify request missing `User-Agent` header → SCP rejected with "No User-Agent" (SCP extracts `requester_nf_type` from this header for routing).  
**Fix**: Added `OGS_SBI_USER_AGENT` header set to `"AMF"` in `amf_namf_comm_build_n2_info_notify()`.

**Bug 3 (Step 10 — lib/sbi/message.c)**: `parse_content()` in SBI message parser didn't know about `n2-info-notify` resource → home AMF returned 400 "Unknown resource name" before the handler could run.  
**Fix**: Added `CASE(OGS_SBI_RESOURCE_NAME_N2_INFO_NOTIFY)` with a no-op body in the NAMF_COMM parse_json switch (N2InformationNotification is parsed manually by the handler).

**Bug 4 (Step 10 — namf-handler.c)**: `amf_sbi_send_release_all_sessions()` called with NULL `param` → assertion failure in `amf_nsmf_pdusession_build_release_sm_context`.  
**Fix**: Declared and initialized `amf_nsmf_pdusession_sm_context_param_t param` with `ue_location=true, ue_timezone=true`, passed `&param` instead of NULL.

---

## Verification

1. Compile: `ninja -C build`
2. Start Home PLMN: `sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp1-999-70.yaml`
3. Start Visiting PLMN: `sudo ./build/tests/app/5gc -c ./build/configs/examples/5gc-sepp2-001-01.yaml`
4. Run tests: `./build/tests/roaming/roaming -c ./build/configs/examples/gnb-999-70-ue-001-01.yaml n2-handover-test -e info`
5. Verify Home AMF logs: Should show CreateUEContext sent (not ErrorIndication)
6. Verify Visiting AMF logs: Should show CreateUEContext received, HandoverRequest sent to target gNB, HandoverRequestAck received, HandoverNotify received
7. Verify test output: All 3 tests pass with HandoverCommand received (not ErrorIndication)

---

## Key Decisions

- **LBO session strategy**: Release-and-reestablish — old PDU sessions released at source SMF after handover; UE establishes new LBO sessions after handover completes. This avoids the complexity of cross-PLMN SMF interaction during handover.
- **PDU sessions in HandoverRequest**: Empty — no sessions are actively transferred to the target gNB during the handover. This is valid per NGAP spec (PDUSessionResourceSetupListHOReq is optional).
- **RANStatusTransfer**: Skipped for initial LBO implementation — no data radio bearers to transfer status for.
- **Deferred SBI response pattern**: Use `ogs_sbi_id_from_stream()` / `ogs_sbi_stream_find_by_id()` on the target AMF to hold the CreateUEContext SBI response until HandoverRequestAck arrives from the target gNB.
- **AMF discovery for N14**: Use TAI-based + target PLMN NRF discovery routed through SEPP, following the same pattern as AUSF/UDM discovery at [sbi-path.c](src/amf/sbi-path.c#L108-L127).

---

## Existing Code Inventory

### What already exists and can be reused

| Component | Status | Location |
|---|---|---|
| `namf-comm` SBI service registration | **Exists** | [src/amf/sbi-path.c](src/amf/sbi-path.c#L42-L50) — allows AMF NF type |
| `UeContextCreateData` OpenAPI model | **Exists** | [lib/sbi/openapi/model/ue_context_create_data.h](lib/sbi/openapi/model/ue_context_create_data.h) |
| `UeContextCreatedData` OpenAPI model | **Exists** | [lib/sbi/openapi/model/ue_context_created_data.h](lib/sbi/openapi/model/ue_context_created_data.h) |
| `N2InformationNotification` OpenAPI model | **Exists** | [lib/sbi/openapi/model/n2_information_notification.h](lib/sbi/openapi/model/n2_information_notification.h) |
| `N2InfoContent` / `NgapIeType` models | **Exists** | [lib/sbi/openapi/model/n2_info_content.h](lib/sbi/openapi/model/n2_info_content.h) |
| `UeContext` / `MmContext` / `PduSessionContext` | **Exists** | [lib/sbi/openapi/model/ue_context.h](lib/sbi/openapi/model/ue_context.h) |
| `NgRanTargetId` model | **Exists** | [lib/sbi/openapi/model/ng_ran_target_id.h](lib/sbi/openapi/model/ng_ran_target_id.h) |
| UE context serialization (KAMF, NAS counts, etc.) | **Exists** | [src/amf/namf-handler.c](src/amf/namf-handler.c#L1427-L1599) — in `handle_ue_context_transfer_request` |
| Intra-PLMN HandoverRequest builder | **Exists** | [src/amf/ngap-build.c](src/amf/ngap-build.c#L2147) — `ngap_build_handover_request()` |
| Intra-PLMN HandoverCommand builder | **Exists** | [src/amf/ngap-build.c](src/amf/ngap-build.c#L2538) — `ngap_build_handover_command()` |
| AMF NRF discovery with GUAMI/TAI | **Exists** | [src/amf/gmm-sm.c](src/amf/gmm-sm.c#L1706-L1734) — used for registration |
| SEPP inter-PLMN SBI routing | **Exists** | [lib/sbi/path.c](lib/sbi/path.c#L737-L795) — auto-routes via SEPP |
| Deferred SBI response pattern | **Exists** | SMF uses `ogs_sbi_id_from_stream()` / `ogs_sbi_stream_find_by_id()` |
| Inter-PLMN detection in HandoverRequired | **Exists** | [src/amf/ngap-handler.c](src/amf/ngap-handler.c#L3309-L3343) — currently rejects |
| Session sync mechanism (`AMF_SESSION_SYNC_DONE`) | **Exists** | [src/amf/context.h](src/amf/context.h#L1079-L1080) |

### What needs to be implemented

| Component | Files to modify/create |
|---|---|
| SBI resource name constant for `n2-info-notify` | [lib/sbi/message.h](lib/sbi/message.h) |
| State constants for inter-AMF handover | [src/amf/sbi-path.h](src/amf/sbi-path.h) |
| Inter-AMF handover fields in `amf_ue_t` | [src/amf/context.h](src/amf/context.h), [src/amf/context.c](src/amf/context.c) |
| `amf_namf_comm_build_create_ue_context()` | [src/amf/namf-build.c](src/amf/namf-build.c), [src/amf/namf-build.h](src/amf/namf-build.h) |
| `amf_namf_comm_handle_create_ue_context_request()` | [src/amf/namf-handler.c](src/amf/namf-handler.c), [src/amf/namf-handler.h](src/amf/namf-handler.h) |
| `amf_namf_comm_handle_create_ue_context_response()` | [src/amf/namf-handler.c](src/amf/namf-handler.c) |
| `amf_namf_comm_build_n2_info_notify()` | [src/amf/namf-build.c](src/amf/namf-build.c) |
| `amf_namf_comm_handle_n2_info_notify()` | [src/amf/namf-handler.c](src/amf/namf-handler.c) |
| SBI server routing for CreateUEContext + N2InfoNotify | [src/amf/amf-sm.c](src/amf/amf-sm.c) |
| SBI client routing for CreateUEContext response | [src/amf/amf-sm.c](src/amf/amf-sm.c), [src/amf/gmm-sm.c](src/amf/gmm-sm.c) |
| Inter-PLMN branch in `ngap_handle_handover_required()` | [src/amf/ngap-handler.c](src/amf/ngap-handler.c) |
| Inter-AMF branch in `ngap_handle_handover_request_ack()` | [src/amf/ngap-handler.c](src/amf/ngap-handler.c) |
| Inter-AMF branch in `ngap_handle_handover_notify()` | [src/amf/ngap-handler.c](src/amf/ngap-handler.c) |
| Inter-AMF branch in `ngap_handle_handover_failure()` | [src/amf/ngap-handler.c](src/amf/ngap-handler.c) |
| Skip RANStatusTransfer for inter-AMF | [src/amf/ngap-handler.c](src/amf/ngap-handler.c) |
| Extend `amf_ue_sbi_discover_and_send()` for AMF target PLMN | [src/amf/sbi-path.c](src/amf/sbi-path.c) |
| Updated inter-PLMN handover tests | [tests/roaming/n2-handover-test.c](tests/roaming/n2-handover-test.c) |
