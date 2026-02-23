/*
 * Copyright (C) 2026 <qfyan@uwaterloo.ca>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "test-common.h"

/* Phase-level timing macros */
#define TIMING_PHASE_START(t) do { (t) = ogs_get_monotonic_time(); } while (0)
#define TIMING_PHASE_END(tag, name, t) \
    ogs_info("[%s][TIMING] %s: %lld ms", tag, name, \
            (long long)(ogs_get_monotonic_time() - (t)) / 1000)
#define TIMING_TOTAL(tag, t) \
    ogs_info("[%s][TIMING] Total: %lld ms", tag, \
            (long long)(ogs_get_monotonic_time() - (t)) / 1000)

/*
 * INTER-PLMN N2 HANDOVER TEST CASES — HOME-ROUTED ROAMING
 *
 * Architecture Under Test:
 * - Home AMF: 127.0.1.5 (PLMN 999-70) - Instance 1
 * - Visiting AMF: 127.0.2.5 (PLMN 001-01) - Instance 2
 * - H-SMF: 127.0.1.4 (PLMN 999-70) - home SMF
 * - V-SMF: 127.0.2.4 (PLMN 001-01) - visited SMF
 * - Two separate AMF instances running with different configs
 * - N14 (Namf_Communication) between AMFs routed through SEPP
 *
 * KEY DIFFERENCE FROM LBO:
 * In home-routed roaming, PDU sessions are maintained through handover.
 * The H-SMF anchor remains, only the V-SMF changes during inter-PLMN HO.
 *
 * N14 INTERFACE (3GPP TS 23.502 §4.9.1.3):
 * 1. Namf_Communication_CreateUEContext - UE context + PDU sessions to target AMF
 * 2. Namf_Communication_N2InfoNotify - Handover completion notification
 * 3. AMF discovery via NRF with SEPP routing
 * 4. HR: PDU sessions transferred in CreateUEContext, V-SMF switched
 *
 * SMF INVOLVEMENT (3GPP TS 29.502):
 * Source side: UpdateSMContext(HANDOVER_REQUIRED) → N2 SM info
 * Target side: CreateSMContext or UpdateSMContext for new V-SMF
 * Completion: UpdateSMContext(HANDOVER_COMPLETED) → V-SMF switch finalized
 *
 * TEST COVERAGE:
 * 1. Basic home-routed inter-PLMN handover (single PDU session)
 * 2. Indirect forwarding home-routed handover
 * 3. Multiple PDU sessions home-routed handover
 * 4. Handover cancellation with session rollback
 * 5. Handover failure with session rollback
 */

/*
 * Helper function to switch PLMN context for NG-Setup and NAS signaling.
 * Updates all PLMN-related fields that affect NG-Setup Request.
 *
 * @param plmn_index: Index into ogs_local_conf()->serving_plmn_id[] array
 *                    0 = Home PLMN (999-70)
 *                    1 = Visiting PLMN (001-01)
 */
static void switch_plmn_context(int plmn_index)
{
    ogs_plmn_id_t *plmn_id;

    ogs_assert(plmn_index < ogs_local_conf()->num_of_serving_plmn_id);
    plmn_id = &ogs_local_conf()->serving_plmn_id[plmn_index];

    /* Update gNB's PLMN support for NG-Setup */
    memcpy(&test_self()->plmn_support[0].plmn_id, plmn_id, OGS_PLMN_ID_LEN);

    /* Update TAI for NG-Setup */
    memcpy(&test_self()->nr_tai.plmn_id, plmn_id, OGS_PLMN_ID_LEN);
    memcpy(&test_self()->nr_cgi.plmn_id, plmn_id, OGS_PLMN_ID_LEN);

    /* Update served TAI list for NG-Setup */
    memcpy(&test_self()->nr_served_tai[0].list0.tai[0].plmn_id,
           plmn_id, OGS_PLMN_ID_LEN);
}

/*
 * Helper: Initialize mobile identity SUCI for test UE
 */
static void setup_mobile_identity_suci(ogs_nas_5gs_mobile_identity_suci_t *suci)
{
    ogs_assert(suci);
    memset(suci, 0, sizeof(*suci));
    suci->h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    suci->h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    suci->routing_indicator1 = 0;
    suci->routing_indicator2 = 0xf;
    suci->routing_indicator3 = 0xf;
    suci->routing_indicator4 = 0xf;
    suci->protection_scheme_id = OGS_PROTECTION_SCHEME_NULL;
    suci->home_network_pki_value = 0;
}

/*
 * Helper: Create and configure test UE with standard parameters
 */
static test_ue_t *create_test_ue(const char *imsi)
{
    ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
    test_ue_t *test_ue = NULL;

    setup_mobile_identity_suci(&mobile_identity_suci);

    test_ue = test_ue_add_by_suci(&mobile_identity_suci, imsi);
    ogs_assert(test_ue);

    test_ue->nr_cgi.cell_id = 0x40001;
    test_ue->nas.registration.tsc = 0;
    test_ue->nas.registration.ksi = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    test_ue->nas.registration.follow_on_request = 1;
    test_ue->nas.registration.value = OGS_NAS_5GS_REGISTRATION_TYPE_INITIAL;
    test_ue->k_string = "465b5ce8b199b49faa5f0a2ee238a6bc";
    test_ue->opc_string = "e8ed289deba952e4283b54e88e6183ca";

    /* HR test: subscriber uses home-routed roaming (lbo_roaming_allowed=false) */
    test_ue->lbo_roaming_allowed = false;

    return test_ue;
}

/*
 * Helper: Perform NG-Setup exchange
 */
static void perform_ng_setup(abts_case *tc, test_ue_t *test_ue,
        ogs_socknode_t *ngap, uint32_t gnb_id, uint32_t tac)
{
    int rv;
    ogs_pkbuf_t *sendbuf, *recvbuf;

    sendbuf = testngap_build_ng_setup_request(gnb_id, tac);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
}

/*
 * Helper: Perform full registration flow with authentication
 */
static void perform_full_registration(abts_case *tc, test_ue_t *test_ue,
        ogs_socknode_t *ngap)
{
    int rv;
    ogs_pkbuf_t *gmmbuf, *nasbuf, *sendbuf, *recvbuf;

    /* Registration Request */
    test_ue->registration_request_param.guti = 1;
    gmmbuf = testgmm_build_registration_request(test_ue, NULL, false, false);
    ABTS_PTR_NOTNULL(tc, gmmbuf);

    test_ue->registration_request_param.gmm_capability = 1;
    test_ue->registration_request_param.s1_ue_network_capability = 1;
    test_ue->registration_request_param.requested_nssai = 1;
    test_ue->registration_request_param.last_visited_registered_tai = 1;
    test_ue->registration_request_param.ue_usage_setting = 1;
    nasbuf = testgmm_build_registration_request(test_ue, NULL, false, false);
    ABTS_PTR_NOTNULL(tc, nasbuf);

    sendbuf = testngap_build_initial_ue_message(test_ue, gmmbuf,
                NGAP_RRCEstablishmentCause_mo_Signalling, false, true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Identity Request/Response */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    gmmbuf = testgmm_build_identity_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Authentication Request/Response */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    gmmbuf = testgmm_build_authentication_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Security Mode Command/Complete */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    gmmbuf = testgmm_build_security_mode_complete(test_ue, nasbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Initial Context Setup */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    sendbuf = testngap_build_ue_radio_capability_info_indication(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    sendbuf = testngap_build_initial_context_setup_response(test_ue, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Registration Complete */
    gmmbuf = testgmm_build_registration_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Configuration Update Command */
    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
}

/*
 * Helper: Establish PDU session
 */
static test_sess_t *establish_pdu_session(abts_case *tc, test_ue_t *test_ue,
        ogs_socknode_t *ngap, const char *dnn, uint8_t psi)
{
    int rv;
    ogs_pkbuf_t *gsmbuf, *gmmbuf, *sendbuf, *recvbuf;
    test_sess_t *sess;

    sess = test_sess_add_by_dnn_and_psi(test_ue, dnn, psi);
    ogs_assert(sess);

    sess->ul_nas_transport_param.request_type = OGS_NAS_5GS_REQUEST_TYPE_INITIAL;
    sess->ul_nas_transport_param.dnn = 1;
    sess->ul_nas_transport_param.s_nssai = 0;
    sess->pdu_session_establishment_param.ssc_mode = 1;
    sess->pdu_session_establishment_param.epco = 1;

    gsmbuf = testgsm_build_pdu_session_establishment_request(sess);
    ABTS_PTR_NOTNULL(tc, gsmbuf);
    gmmbuf = testgmm_build_ul_nas_transport(sess,
            OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, gsmbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    sendbuf = testngap_sess_build_pdu_session_resource_setup_response(sess);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    return sess;
}

/*
 * TEST 1: Basic Home-Routed Inter-PLMN N2 Handover (Single PDU Session)
 *
 * Setup:
 *   - UE registered in Visiting PLMN (001-01) with home-routed session
 *   - PDU session: V-SMF (001-01) → H-SMF (999-70) → H-UPF (999-70)
 *   - Source gNB 0x4000 in Visiting PLMN (001-01)
 *
 * Action: Handover from Visiting PLMN to Home PLMN
 *
 * Expected Behavior (Home-Routed):
 *   - Visiting AMF detects inter-PLMN target, discovers Home AMF via NRF/SEPP
 *   - Visiting AMF sends UpdateSMContext(HANDOVER_REQUIRED) to V-SMF
 *   - V-SMF forwards to H-SMF, H-SMF returns N2 SM Information
 *   - Visiting AMF sends CreateUEContext (with PDU sessions) to Home AMF
 *   - Home AMF selects new V-SMF (or uses H-SMF directly) for target
 *   - Home AMF sends HandoverRequest to target gNB (WITH PDU sessions)
 *   - Target gNB responds HandoverRequestAck
 *   - Home AMF responds CreateUEContext to Visiting AMF
 *   - Visiting AMF sends HandoverCommand to source gNB
 *   - Target gNB sends HandoverNotify to Home AMF
 *   - Home AMF sends N2InfoNotify(HANDOVER_COMPLETED) to Visiting AMF
 *   - V-SMF switch completed: old V-SMF released, new V-SMF active
 *
 * 3GPP: TS 23.502 §4.9.1.3.2, §4.23.7 (V-SMF change during handover)
 */
static void test1_func(abts_case *tc, void *data)
{
    ogs_info("[HR-TEST1] ========================================");
    ogs_info("[HR-TEST1] Home-Routed Inter-PLMN N2 Handover");
    ogs_info("[HR-TEST1] Single PDU Session");
    ogs_info("[HR-TEST1] ========================================");
    ogs_info("[HR-TEST1] PLACEHOLDER - Implementation in Phase 1");
    ogs_info("[HR-TEST1] ========================================");

    /* TODO: Phase 1A-1E implementation
     *
     * This test will validate:
     * 1. Source AMF involves SMF before CreateUEContext
     *    (AMF_UPDATE_SM_CONTEXT_INTER_PLMN_HANDOVER_REQUIRED)
     * 2. CreateUEContext carries PDU session context list
     * 3. Target AMF processes PDU sessions from CreateUEContext
     * 4. HandoverRequest includes PDU session resources
     * 5. V-SMF switch completes on HandoverNotify
     * 6. Data path works through H-SMF after handover
     */
}

/*
 * TEST 2: Indirect Forwarding Home-Routed Inter-PLMN Handover
 *
 * Same as test1 but with indirect forwarding tunnel setup.
 * Inter-PLMN handovers typically use indirect forwarding since
 * gNBs in different PLMNs lack direct Xn connectivity.
 *
 * 3GPP: TS 23.502 §4.9.1.3.2, §4.9.1.3.3 (indirect forwarding)
 */
static void test2_func(abts_case *tc, void *data)
{
    ogs_info("[HR-TEST2] ========================================");
    ogs_info("[HR-TEST2] Home-Routed Inter-PLMN N2 Handover");
    ogs_info("[HR-TEST2] Indirect Forwarding");
    ogs_info("[HR-TEST2] ========================================");
    ogs_info("[HR-TEST2] PLACEHOLDER - Implementation in Phase 1E");
    ogs_info("[HR-TEST2] ========================================");

    /* TODO: Phase 1E implementation
     *
     * This test will validate:
     * 1. All of test1 plus indirect forwarding tunnel
     * 2. CreateIndirectDataForwardingTunnelRequest/Response
     * 3. Data forwarding during handover execution
     * 4. Tunnel teardown after completion
     */
}

/*
 * TEST 3: Multiple PDU Sessions Home-Routed Inter-PLMN Handover
 *
 * Setup:
 *   - UE with 2+ active home-routed PDU sessions
 *
 * Action: Handover all sessions together
 *
 * Expected: All PDU sessions transferred, V-SMF switch for each
 *
 * 3GPP: TS 23.502 §4.9.1.3.2
 */
static void test3_func(abts_case *tc, void *data)
{
    ogs_info("[HR-TEST3] ========================================");
    ogs_info("[HR-TEST3] Home-Routed Inter-PLMN N2 Handover");
    ogs_info("[HR-TEST3] Multiple PDU Sessions");
    ogs_info("[HR-TEST3] ========================================");
    ogs_info("[HR-TEST3] PLACEHOLDER - Implementation in Phase 1");
    ogs_info("[HR-TEST3] ========================================");

    /* TODO: Phase 1 implementation
     *
     * This test will validate:
     * 1. Multiple PDU sessions in CreateUEContext
     * 2. AMF_SESSION_SYNC_DONE waits for all SMF responses
     * 3. All sessions transferred in HandoverRequest
     * 4. V-SMF switch for each session
     */
}

/*
 * TEST 4: Handover Cancellation with Home-Routed Session Rollback
 *
 * Setup: UE with home-routed session, handover in progress
 * Action: Source gNB sends HandoverCancel after HandoverCommand
 *
 * Expected: SMF state rolled back, sessions restored on source side
 *
 * 3GPP: TS 23.502 §4.9.1.3.4 (handover cancel)
 */
static void test4_func(abts_case *tc, void *data)
{
    ogs_info("[HR-TEST4] ========================================");
    ogs_info("[HR-TEST4] Home-Routed Inter-PLMN N2 Handover");
    ogs_info("[HR-TEST4] Handover Cancel + Session Rollback");
    ogs_info("[HR-TEST4] ========================================");
    ogs_info("[HR-TEST4] PLACEHOLDER - Implementation in Phase 2");
    ogs_info("[HR-TEST4] ========================================");

    /* TODO: Phase 2 implementation
     *
     * This test will validate:
     * 1. HandoverCancel triggers SMF context rollback
     * 2. Target AMF UE context released
     * 3. V-SMF switch undone, original V-SMF restored
     * 4. Data path works again through original path
     */
}

/*
 * TEST 5: Handover Failure with Home-Routed Session Rollback
 *
 * Setup: UE with home-routed session
 * Action: Target gNB rejects HandoverRequest
 *
 * Expected: HandoverPreparationFailure, SMF state rolled back
 *
 * 3GPP: TS 23.502 §4.9.1.3.4 (handover failure)
 */
static void test5_func(abts_case *tc, void *data)
{
    ogs_info("[HR-TEST5] ========================================");
    ogs_info("[HR-TEST5] Home-Routed Inter-PLMN N2 Handover");
    ogs_info("[HR-TEST5] Handover Failure + Session Rollback");
    ogs_info("[HR-TEST5] ========================================");
    ogs_info("[HR-TEST5] PLACEHOLDER - Implementation in Phase 2");
    ogs_info("[HR-TEST5] ========================================");

    /* TODO: Phase 2 implementation
     *
     * This test will validate:
     * 1. HandoverFailure triggers preparation failure
     * 2. SMF context rolled back
     * 3. V-SMF switch undone, original V-SMF restored
     * 4. CreateUEContext error path cleanup
     */
}

abts_suite *test_n2_handover_hr(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    ogs_info("========================================");
    ogs_info("Inter-PLMN N2 Handover HR Test Suite");
    ogs_info("========================================");
    ogs_info("Architecture Under Test:");
    ogs_info("  - Home AMF (999-70): 127.0.1.5");
    ogs_info("  - Visiting AMF (001-01): 127.0.2.5");
    ogs_info("  - H-SMF (999-70): 127.0.1.4");
    ogs_info("  - V-SMF (001-01): 127.0.2.4");
    ogs_info("  - N14 (Namf_Communication) between AMFs via SEPP");
    ogs_info("  - Home-Routed: PDU sessions preserved during handover");
    ogs_info(" ");

    abts_run_test(suite, test1_func, NULL);
    abts_run_test(suite, test2_func, NULL);
    abts_run_test(suite, test3_func, NULL);
    abts_run_test(suite, test4_func, NULL);
    abts_run_test(suite, test5_func, NULL);

    ogs_info(" ");
    ogs_info("========================================");
    ogs_info("HR Test Suite Summary (5 Tests):");
    ogs_info(" ");
    ogs_info("1. Basic Home-Routed Inter-PLMN Handover");
    ogs_info("   Single PDU session, V-SMF switch");
    ogs_info("   Status: PLACEHOLDER");
    ogs_info(" ");
    ogs_info("2. Indirect Forwarding Home-Routed");
    ogs_info("   Inter-PLMN default (no direct Xn)");
    ogs_info("   Status: PLACEHOLDER");
    ogs_info(" ");
    ogs_info("3. Multiple PDU Sessions Home-Routed");
    ogs_info("   All sessions transferred + V-SMF switch");
    ogs_info("   Status: PLACEHOLDER");
    ogs_info(" ");
    ogs_info("4. Handover Cancel (HR Session Rollback)");
    ogs_info("   Source cancels, SMF state restored");
    ogs_info("   Status: PLACEHOLDER");
    ogs_info(" ");
    ogs_info("5. Handover Failure (HR Session Rollback)");
    ogs_info("   Target rejects, SMF state restored");
    ogs_info("   Status: PLACEHOLDER");
    ogs_info(" ");
    ogs_info("========================================");

    return suite;
}
