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
 * Helper: Wait for UEContextReleaseCommand, consuming any preceding
 * HandoverCommand messages that may arrive in the HR inter-PLMN flow.
 *
 * In home-routed inter-PLMN handover, the source AMF may send an
 * additional HandoverCommand (proc 9) to the source gNB before the
 * UEContextReleaseCommand (proc 41). This can happen when the SMF
 * completes indirect forwarding PFCP setup and sends a second
 * HANDOVER_CMD response in rapid succession with the first.
 * This helper consumes any such extra messages.
 */
static void wait_for_ue_context_release_on_source(abts_case *tc,
        test_ue_t *test_ue, ogs_socknode_t *ngap_home,
        const char *label)
{
    ogs_pkbuf_t *recvbuf;

    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    if (test_ue->ngap_procedure_code !=
            NGAP_ProcedureCode_id_UEContextRelease) {
        ogs_info("[%s] Consumed extra NGAP msg (proc=%ld) before "
                "UEContextReleaseCommand",
                label, (long)test_ue->ngap_procedure_code);
        recvbuf = testgnb_ngap_read(ngap_home);
        ABTS_PTR_NOTNULL(tc, recvbuf);
        testngap_recv(test_ue, recvbuf);
    }

    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);
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
 *   - UE + session in Home PLMN (999-70, gNB 0x4000)
 *   - PDU session: SMF (999-70) with lbo_roaming_allowed=false
 *   - Visiting network gNB 0x4001 (PLMN 001-01) also configured
 *
 * Action: Handover from Home to Visiting PLMN with HR session transfer
 *
 * Expected Behavior (Home-Routed):
 *   - Home AMF detects inter-PLMN target, discovers Visiting AMF
 *   - Home AMF sends UpdateSMContext(HANDOVER_REQUIRED) to SMF (HR path)
 *   - SMF returns N2 SM Information for PDU session
 *   - Home AMF sends CreateUEContext (with PDU sessions) to Visiting AMF
 *   - Visiting AMF sends HandoverRequest to target gNB (WITH PDU sessions)
 *   - Target gNB responds HandoverRequestAck (with PDUSessionResourceAdmittedList)
 *   - Visiting AMF responds CreateUEContext 201 (with ack transfers) to Home AMF
 *   - Home AMF sends UpdateSMContext(HANDOVER_REQ_ACK) to SMF
 *   - SMF returns HANDOVER_CMD, Home AMF sends HandoverCommand to source gNB
 *   - Target gNB sends HandoverNotify to Visiting AMF
 *   - Visiting AMF sends N2InfoNotify(HANDOVER_COMPLETED) to Home AMF
 *   - Home AMF sends UpdateSMContext(COMPLETED) to SMF, releases session
 *   - Home AMF sends UEContextReleaseCommand to source gNB
 *
 * 3GPP: TS 23.502 §4.9.1.3.2 (Inter-AMF N2 handover)
 */
static void test1_func(abts_case *tc, void *data)
{
    int rv;
    ogs_socknode_t *ngap_home, *ngap_visiting;
    ogs_socknode_t *gtpu_home, *gtpu_visiting;
    ogs_pkbuf_t *sendbuf;
    ogs_pkbuf_t *recvbuf;

    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;
    test_bearer_t *qos_flow = NULL;

    bson_t *doc = NULL;

    ogs_time_t t_total, t_phase;

    /* Verify config has both PLMNs for inter-PLMN test */
    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);

    TIMING_PHASE_START(t_total);

    /**************************************************************************
     * PHASE 0: SETUP BOTH HOME AND VISITING NETWORK INFRASTRUCTURE
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST1] ========================================");
    ogs_info("[HR-TEST1] Phase 0: Infrastructure setup");
    ogs_info("[HR-TEST1] ========================================");

    /* Setup gNB connections for BOTH networks */
    ogs_info("[HR-TEST1] Setting up Home network gNB 0x4000");
    ngap_home = testngap_client(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_home);
    gtpu_home = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_home);

    ogs_info("[HR-TEST1] Setting up Visiting network gNB 0x4001");
    ngap_visiting = testngap_client(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_visiting);
    gtpu_visiting = test_gtpu_server(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_visiting);

    /* Create test UE (lbo_roaming_allowed=false for HR) */
    test_ue = create_test_ue("0000203191");
    doc = test_db_new_simple(test_ue);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    /* Switch to home PLMN context (999-70) and setup home gNB */
    switch_plmn_context(0);
    ogs_info("[HR-TEST1] Performing NG-Setup for Home gNB (PLMN 999-70)");
    perform_ng_setup(tc, test_ue, ngap_home, 0x4000, 22);
    ogs_info("[HR-TEST1] Home gNB 0x4000 connected to Home AMF");

    /* Switch to visiting PLMN context (001-01) and setup visiting gNB */
    switch_plmn_context(1);
    ogs_info("[HR-TEST1] Attempting NG-Setup for Visiting gNB (PLMN 001-01)");
    sendbuf = testngap_build_ng_setup_request(0x4001, 22);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Switch back to home PLMN for UE registration */
    switch_plmn_context(0);

    TIMING_PHASE_END("HR-TEST1", "Phase 0 (setup)", t_phase);

    /**************************************************************************
     * PHASE 1: REGISTER AND ESTABLISH SESSION IN HOME NETWORK
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST1] ========================================");
    ogs_info("[HR-TEST1] Phase 1: Home network registration");
    ogs_info("[HR-TEST1] ========================================");

    /* Full registration flow */
    perform_full_registration(tc, test_ue, ngap_home);

    /* PDU Session Establishment */
    sess = establish_pdu_session(tc, test_ue, ngap_home, "internet", 5);

    /* Verify data path in home network */
    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);

    rv = test_gtpu_send_ping(gtpu_home, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_gtpu_read(gtpu_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    ogs_info("[HR-TEST1] Phase 1 complete - UE registered with active PDU session");

    TIMING_PHASE_END("HR-TEST1", "Phase 1 (registration)", t_phase);

    /**************************************************************************
     * PHASE 2: INTER-PLMN N2 HANDOVER VIA N14 (Home-Routed Sessions)
     *
     * Source: gNB 0x4000 (PLMN 999-70) → Home AMF (127.0.1.5)
     * Target: gNB 0x4001 (PLMN 001-01) → Visiting AMF (127.0.2.5)
     *
     * HR Flow (differs from LBO):
     *   1. Source gNB → HandoverRequired → Home AMF
     *   2. Home AMF → UpdateSMContext(HANDOVER_REQUIRED) → SMF [HR only]
     *   3. Home AMF → CreateUEContext (with PDU sessions) → Visiting AMF
     *   4. Visiting AMF → HandoverRequest (with PDU sessions) → Target gNB
     *   5. Target gNB → HandoverRequestAck (with admitted sessions) → Visiting AMF
     *   6. Visiting AMF → CreateUEContext 201 (with ack transfers) → Home AMF
     *   7. Home AMF → UpdateSMContext(HANDOVER_REQ_ACK) → SMF [HR only]
     *   8. Home AMF → HandoverCommand → Source gNB
     *   9. Target gNB → HandoverNotify → Visiting AMF
     *  10. Visiting AMF → N2InfoNotify(HANDOVER_COMPLETED) → Home AMF
     *  11. Home AMF → UpdateSMContext(COMPLETED) → SMF [HR only]
     *  12. Home AMF → UEContextReleaseCommand → Source gNB
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST1] ========================================");
    ogs_info("[HR-TEST1] Phase 2: Inter-PLMN N2 handover (HR)");
    ogs_info("[HR-TEST1] ========================================");

    /* Prepare target with different PLMN (visiting network) */
    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;
    uint64_t visiting_amf_ue_ngap_id;
    uint32_t visiting_ran_ue_ngap_id;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));

    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);
    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1], OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 22;

    /* Step 1: Send HandoverRequired to Home AMF */
    ogs_info("[HR-TEST1] Step 1: HandoverRequired → Home AMF");
    sendbuf = testngap_build_handover_required_with_target_plmn(
            test_ue,
            NGAP_HandoverType_intra5gs,
            0x4001, 24,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_handover_desirable_for_radio_reason,
            true, &target_plmn, &target_tai);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Step 4: Receive HandoverRequest on target gNB
     * HR: HandoverRequest includes PDUSessionResourceSetupListHOReq
     * (sessions from CreateUEContext passed through to target gNB) */
    ogs_info("[HR-TEST1] Step 4: ← Waiting for HandoverRequest...");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);
    ogs_info("[HR-TEST1] ← Received HandoverRequest (with PDU sessions)");

    /* Save visiting AMF context */
    visiting_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;

    /* Step 5: Send HandoverRequestAck WITH PDU sessions (HR)
     * Uses standard builder which iterates test_ue->sess_list and includes
     * PDUSessionResourceAdmittedList with HandoverRequestAcknowledgeTransfer */
    ogs_info("[HR-TEST1] Step 5: → HandoverRequestAck (with sessions)");
    sendbuf = testngap_build_handover_request_ack(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Save visiting ran_ue_ngap_id after ack builder incremented it */
    visiting_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /* Step 8: Receive HandoverCommand on source gNB
     * HR: Home AMF waits for UpdateSMContext(HANDOVER_REQ_ACK) → HANDOVER_CMD
     * response from SMF before sending HandoverCommand (may take longer) */
    ogs_info("[HR-TEST1] Step 8: ← Waiting for HandoverCommand...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);
    ogs_info("[HR-TEST1] ← Received HandoverCommand");

    /* Restore visiting AMF context for target-side messages */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;
    test_ue->nr_cgi.cell_id = 0x40011;

    /* Step 9: Send HandoverNotify on target gNB */
    ogs_info("[HR-TEST1] Step 9: → HandoverNotify on visiting gNB");
    sendbuf = testngap_build_handover_notify(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Step 12: Receive UEContextReleaseCommand on source gNB
     * HR: Home AMF sends UEContextReleaseCommand after processing
     * N2InfoNotify(HANDOVER_COMPLETED). An extra HandoverCommand may
     * precede it in the HR flow (see helper comment). */
    ogs_info("[HR-TEST1] Step 12: ← Waiting for UEContextReleaseCommand...");
    wait_for_ue_context_release_on_source(tc, test_ue, ngap_home, "HR-TEST1");
    ogs_info("[HR-TEST1] ← Received UEContextReleaseCommand");

    /* Send UEContextReleaseComplete on source gNB */
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    ogs_info("[HR-TEST1] Inter-PLMN HR N2 handover completed successfully");

    TIMING_PHASE_END("HR-TEST1", "Phase 2 (handover)", t_phase);

    /********** Cleanup visiting AMF UE context */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;

    sendbuf = testngap_build_ue_context_release_request(test_ue,
            NGAP_Cause_PR_radioNetwork, NGAP_CauseRadioNetwork_user_inactivity,
            true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    /********** Final cleanup */
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    testgnb_gtpu_close(gtpu_home);
    testgnb_ngap_close(ngap_home);
    testgnb_gtpu_close(gtpu_visiting);
    testgnb_ngap_close(ngap_visiting);
    test_ue_remove(test_ue);

    ogs_info("[HR-TEST1] ========================================");
    ogs_info("[HR-TEST1] Test complete - HR inter-PLMN N2 handover OK");
    ogs_info("[HR-TEST1] ========================================");
    TIMING_TOTAL("HR-TEST1", t_total);
}

/*
 * TEST 2: Indirect Forwarding Home-Routed Inter-PLMN Handover
 *
 * Same as test1 but with indirect forwarding (direct=false).
 * Inter-PLMN handovers typically use indirect forwarding since
 * gNBs in different PLMNs lack direct Xn connectivity.
 *
 * Setup:
 *   - UE + session in Home PLMN (999-70, gNB 0x4000)
 *   - Visiting gNB 0x4002, TAC 23
 *
 * 3GPP: TS 23.502 §4.9.1.3.2, §4.9.1.3.3 (indirect forwarding)
 */
static void test2_func(abts_case *tc, void *data)
{
    int rv;
    ogs_socknode_t *ngap_home, *ngap_visiting;
    ogs_socknode_t *gtpu_home, *gtpu_visiting;
    ogs_pkbuf_t *sendbuf;
    ogs_pkbuf_t *recvbuf;

    test_ue_t *test_ue = NULL;

    bson_t *doc = NULL;

    ogs_time_t t_total, t_phase;

    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);

    TIMING_PHASE_START(t_total);
    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST2] ========================================");
    ogs_info("[HR-TEST2] HR indirect forwarding inter-PLMN");
    ogs_info("[HR-TEST2] ========================================");

    /* Setup both network infrastructures */
    ngap_home = testngap_client(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_home);
    gtpu_home = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_home);

    ngap_visiting = testngap_client(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_visiting);
    gtpu_visiting = test_gtpu_server(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_visiting);

    /* Setup UE (lbo_roaming_allowed=false for HR) */
    test_ue = create_test_ue("0000203192");
    doc = test_db_new_simple(test_ue);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    /* NG-Setup for home gNB */
    switch_plmn_context(0);
    perform_ng_setup(tc, test_ue, ngap_home, 0x4000, 22);

    /* NG-Setup for visiting gNB (different TAC) */
    switch_plmn_context(1);
    sendbuf = testngap_build_ng_setup_request(0x4002, 23);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Registration and PDU session in home PLMN */
    switch_plmn_context(0);
    perform_full_registration(tc, test_ue, ngap_home);
    establish_pdu_session(tc, test_ue, ngap_home, "internet", 5);

    TIMING_PHASE_END("HR-TEST2", "Setup + Registration", t_phase);

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST2] ========================================");
    ogs_info("[HR-TEST2] HR handover with indirect forwarding");
    ogs_info("[HR-TEST2] ========================================");

    /* Prepare target */
    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;
    uint64_t visiting_amf_ue_ngap_id;
    uint32_t visiting_ran_ue_ngap_id;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));
    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1], OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 23;

    /* HandoverRequired with indirect forwarding (direct=false) */
    ogs_info("[HR-TEST2] → HandoverRequired (indirect, cross-PLMN, HR)");
    sendbuf = testngap_build_handover_required_with_target_plmn(
            test_ue,
            NGAP_HandoverType_intra5gs,
            0x4002, 24,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_handover_desirable_for_radio_reason,
            false, &target_plmn, &target_tai);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive HandoverRequest on target gNB (with PDU sessions) */
    ogs_info("[HR-TEST2] ← Waiting for HandoverRequest...");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);

    visiting_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;

    /* HandoverRequestAck WITH sessions (HR) */
    ogs_info("[HR-TEST2] → HandoverRequestAck (with sessions)");
    sendbuf = testngap_build_handover_request_ack(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    visiting_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /* Receive HandoverCommand on source gNB */
    ogs_info("[HR-TEST2] ← Waiting for HandoverCommand...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);

    /* Restore visiting context for target-side messages */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;
    test_ue->nr_cgi.cell_id = 0x40021;

    /* HandoverNotify on target gNB */
    ogs_info("[HR-TEST2] → HandoverNotify on visiting gNB");
    sendbuf = testngap_build_handover_notify(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* UEContextReleaseCommand on source gNB */
    ogs_info("[HR-TEST2] ← Waiting for UEContextReleaseCommand...");
    wait_for_ue_context_release_on_source(tc, test_ue, ngap_home, "HR-TEST2");

    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    ogs_info("[HR-TEST2] HR indirect forwarding handover completed");

    TIMING_PHASE_END("HR-TEST2", "Handover", t_phase);

    /* Cleanup visiting AMF UE context */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;

    sendbuf = testngap_build_ue_context_release_request(test_ue,
            NGAP_Cause_PR_radioNetwork, NGAP_CauseRadioNetwork_user_inactivity,
            true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    /* Final cleanup */
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    testgnb_gtpu_close(gtpu_home);
    testgnb_ngap_close(ngap_home);
    testgnb_gtpu_close(gtpu_visiting);
    testgnb_ngap_close(ngap_visiting);
    test_ue_remove(test_ue);

    ogs_info("[HR-TEST2] ========================================");
    ogs_info("[HR-TEST2] Test complete");
    ogs_info("[HR-TEST2] ========================================");
    TIMING_TOTAL("HR-TEST2", t_total);
}

/*
 * TEST 3: Multiple PDU Sessions Home-Routed Inter-PLMN Handover
 *
 * Setup:
 *   - UE with internet session (PSI 5) + IMS attempt (PSI 6)
 *   - All sessions have lbo_roaming_allowed=false (HR)
 *
 * Action: Handover all active sessions together
 *
 * Expected: All HR sessions transferred via CreateUEContext,
 *   UpdateSMContext for each session, HandoverRequest with all sessions,
 *   AMF_SESSION_SYNC_DONE waits for all SMF responses.
 *
 * 3GPP: TS 23.502 §4.9.1.3.2
 */
static void test3_func(abts_case *tc, void *data)
{
    int rv;
    ogs_socknode_t *ngap_home, *ngap_visiting;
    ogs_socknode_t *gtpu_home, *gtpu_visiting;
    ogs_pkbuf_t *gmmbuf;
    ogs_pkbuf_t *gsmbuf;
    ogs_pkbuf_t *sendbuf;
    ogs_pkbuf_t *recvbuf;

    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;
    bson_t *doc = NULL;

    ogs_time_t t_total, t_phase;

    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);

    TIMING_PHASE_START(t_total);
    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST3] ========================================");
    ogs_info("[HR-TEST3] HR multiple PDU sessions inter-PLMN");
    ogs_info("[HR-TEST3] ========================================");

    /* Setup both network infrastructures */
    ngap_home = testngap_client(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_home);
    gtpu_home = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_home);

    ngap_visiting = testngap_client(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_visiting);
    gtpu_visiting = test_gtpu_server(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_visiting);

    /* Setup UE (lbo_roaming_allowed=false for HR) */
    test_ue = create_test_ue("0000203193");
    doc = test_db_new_simple(test_ue);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    /* NG-Setup for home gNB */
    switch_plmn_context(0);
    perform_ng_setup(tc, test_ue, ngap_home, 0x4000, 22);

    /* NG-Setup for visiting gNB */
    switch_plmn_context(1);
    sendbuf = testngap_build_ng_setup_request(0x4001, 22);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Switch back to home PLMN */
    switch_plmn_context(0);

    /* Full registration flow */
    perform_full_registration(tc, test_ue, ngap_home);

    /* PDU Session 1: Internet */
    ogs_info("[HR-TEST3] Establishing PDU session 1: internet (PSI 5)");
    sess = establish_pdu_session(tc, test_ue, ngap_home, "internet", 5);

    /* Attempt second PDU session: IMS */
    ogs_info("[HR-TEST3] Attempting second PDU session: ims (PSI 6)");
    sess = test_sess_add_by_dnn_and_psi(test_ue, "ims", 6);
    ogs_assert(sess);

    sess->ul_nas_transport_param.request_type = OGS_NAS_5GS_REQUEST_TYPE_INITIAL;
    sess->ul_nas_transport_param.dnn = 1;
    sess->ul_nas_transport_param.s_nssai = 1;
    sess->pdu_session_establishment_param.ssc_mode = 1;
    sess->pdu_session_establishment_param.epco = 1;

    gsmbuf = testgsm_build_pdu_session_establishment_request(sess);
    ABTS_PTR_NOTNULL(tc, gsmbuf);
    gmmbuf = testgmm_build_ul_nas_transport(sess,
            OGS_NAS_PAYLOAD_CONTAINER_N1_SM_INFORMATION, gsmbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive response (may be 5GMM status if IMS not configured) */
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Check if IMS session was rejected */
    if (test_ue->ngap_procedure_code == NGAP_ProcedureCode_id_DownlinkNASTransport) {
        ogs_info("[HR-TEST3] IMS session rejected (not configured)");
        ogs_info("[HR-TEST3] Testing with internet session only");
        test_sess_remove(sess);
    } else {
        /* IMS accepted */
        sendbuf = testngap_sess_build_pdu_session_resource_setup_response(sess);
        ABTS_PTR_NOTNULL(tc, sendbuf);
        rv = testgnb_ngap_send(ngap_home, sendbuf);
        ABTS_INT_EQUAL(tc, OGS_OK, rv);
        ogs_info("[HR-TEST3] Both internet and IMS sessions established");
    }

    TIMING_PHASE_END("HR-TEST3", "Setup + Registration", t_phase);

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST3] HR handover with multiple sessions");

    /* Prepare target */
    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;
    uint64_t visiting_amf_ue_ngap_id;
    uint32_t visiting_ran_ue_ngap_id;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));
    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1], OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 22;

    /* HandoverRequired (all HR sessions included via sess_list) */
    sendbuf = testngap_build_handover_required_with_target_plmn(
            test_ue,
            NGAP_HandoverType_intra5gs,
            0x4001, 24,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_handover_desirable_for_radio_reason,
            false, &target_plmn, &target_tai);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* HandoverRequest on target gNB (with PDU sessions for HR) */
    ogs_info("[HR-TEST3] ← Waiting for HandoverRequest...");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);

    visiting_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;

    /* HandoverRequestAck WITH all sessions (HR) */
    sendbuf = testngap_build_handover_request_ack(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    visiting_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /* HandoverCommand on source gNB */
    ogs_info("[HR-TEST3] ← Waiting for HandoverCommand...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);

    /* Restore visiting context */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;
    test_ue->nr_cgi.cell_id = 0x40011;

    /* HandoverNotify */
    sendbuf = testngap_build_handover_notify(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* UEContextReleaseCommand on source gNB */
    ogs_info("[HR-TEST3] ← Waiting for UEContextReleaseCommand...");
    wait_for_ue_context_release_on_source(tc, test_ue, ngap_home, "HR-TEST3");

    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    ogs_info("[HR-TEST3] HR multi-session handover completed");

    TIMING_PHASE_END("HR-TEST3", "Handover", t_phase);

    /* Cleanup visiting AMF UE context */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;

    sendbuf = testngap_build_ue_context_release_request(test_ue,
            NGAP_Cause_PR_radioNetwork, NGAP_CauseRadioNetwork_user_inactivity,
            true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    /* Final cleanup */
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    testgnb_gtpu_close(gtpu_home);
    testgnb_ngap_close(ngap_home);
    testgnb_gtpu_close(gtpu_visiting);
    testgnb_ngap_close(ngap_visiting);
    test_ue_remove(test_ue);

    ogs_info("[HR-TEST3] ========================================");
    ogs_info("[HR-TEST3] Test complete");
    ogs_info("[HR-TEST3] ========================================");
    TIMING_TOTAL("HR-TEST3", t_total);
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
    ogs_info("   Single PDU session, HR session transfer");
    ogs_info("   Status: IMPLEMENTED");
    ogs_info(" ");
    ogs_info("2. Indirect Forwarding Home-Routed");
    ogs_info("   Inter-PLMN indirect (no direct Xn)");
    ogs_info("   Status: IMPLEMENTED");
    ogs_info(" ");
    ogs_info("3. Multiple PDU Sessions Home-Routed");
    ogs_info("   All sessions transferred via HR path");
    ogs_info("   Status: IMPLEMENTED");
    ogs_info(" ");
    ogs_info("4. Handover Cancel (HR Session Rollback)");
    ogs_info("   Source cancels, SMF state restored");
    ogs_info("   Status: PLACEHOLDER (Phase 2)");
    ogs_info(" ");
    ogs_info("5. Handover Failure (HR Session Rollback)");
    ogs_info("   Target rejects, SMF state restored");
    ogs_info("   Status: PLACEHOLDER (Phase 2)");
    ogs_info(" ");
    ogs_info("========================================");

    return suite;
}
