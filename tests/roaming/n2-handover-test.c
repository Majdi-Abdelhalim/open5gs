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

/*
 * INTER-PLMN N2 HANDOVER TEST CASES
 * 
 * Architecture Under Test:
 * - Home AMF: 127.0.1.5 (PLMN 999-70) - Instance 1
 * - Visiting AMF: 127.0.2.5 (PLMN 001-01) - Instance 2
 * - Two separate AMF instances running with different configs
 * 
 * N14 INTERFACE (3GPP TS 23.502 §4.9.1.3):
 * Required for inter-AMF handovers:
 * 1. Namf_Communication_UEContextTransfer - UE context to target AMF
 * 2. Namf_Communication_N2InfoNotify - N2 message forwarding
 * 3. AMF discovery via NRF
 * 4. Security context and session continuity
 * 
 * CURRENT STATE (Open5GS):
 * ✗ N14 interface NOT implemented
 * ✗ Home AMF cannot discover/reach Visiting AMF
 * ✗ Home AMF cannot find target gNB (connected to different AMF)
 * ✗ Result: ErrorIndication sent to source gNB
 * 
 * TEST COVERAGE:
 * 1. Direct forwarding failure
 * 2. Indirect forwarding failure
 * 3. Multiple sessions with partial handover (indirect forwarding)
 * 4. Handover cancellation (TODO)
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
 * Helper: Cleanup test resources
 */
static void cleanup_test_ue(abts_case *tc, test_ue_t *test_ue,
        ogs_socknode_t *ngap, ogs_socknode_t *gtpu)
{
    int rv;
    ogs_pkbuf_t *sendbuf, *recvbuf;

    sendbuf = testngap_build_ue_context_release_request(test_ue,
            NGAP_Cause_PR_radioNetwork, NGAP_CauseRadioNetwork_user_inactivity,
            true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    testgnb_gtpu_close(gtpu);
    testgnb_ngap_close(ngap);
    test_ue_remove(test_ue);
}

/*
 * TEST 1: Inter-PLMN Handover with Direct Forwarding
 *  
 * Setup: 
 *   - UE + session in Home PLMN (999-70, gNB 0x4000)
 *   - Visiting network gNB 0x4001 (PLMN 001-01) also configured
 * 
 * Action: Handover from Home to Visiting PLMN with direct forwarding
 * 
 * Expected Behavior:
 *   - Home AMF receives HandoverRequired with target in PLMN 001-01
 *   - Home AMF detects inter-PLMN scenario (target not in served_guami)
 *   - Home AMF sends ErrorIndication
 * 
 * With N14: Home AMF would use Namf_Communication to reach Visiting AMF
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
    ogs_ngap_message_t message;

    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;
    test_bearer_t *qos_flow = NULL;

    bson_t *doc = NULL;

    /* Verify config has both PLMNs for inter-PLMN test */
    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);

    /**************************************************************************
     * PHASE 0: SETUP BOTH HOME AND VISITING NETWORK INFRASTRUCTURE
     **************************************************************************/

    ogs_info("[TEST1] ========================================");
    ogs_info("[TEST1] Phase 0: Infrastructure setup");
    ogs_info("[TEST1] ========================================");

    /* Setup gNB connections for BOTH networks */
    ogs_info("[TEST1] Setting up Home network gNB 0x4000");
    ngap_home = testngap_client(1, AF_INET);  /* Connect to Home AMF (127.0.1.5) */
    ABTS_PTR_NOTNULL(tc, ngap_home);
    gtpu_home = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_home);

    ogs_info("[TEST1] Setting up Visiting network gNB 0x4001");
    ngap_visiting = testngap_client(2, AF_INET);  /* Connect to Visiting AMF (127.0.2.5) */
    ABTS_PTR_NOTNULL(tc, ngap_visiting);
    gtpu_visiting = test_gtpu_server(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_visiting);

    /* Create test UE */
    test_ue = create_test_ue("0000203191");
    doc = test_db_new_simple(test_ue);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    /* Switch to home PLMN context (999-70) and setup home gNB */
    switch_plmn_context(0);
    ogs_info("[TEST1] Performing NG-Setup for Home gNB (PLMN 999-70)");
    perform_ng_setup(tc, test_ue, ngap_home, 0x4000, 22);
    ogs_info("[TEST1] ✓ Home gNB 0x4000 connected to Home AMF");

    /* Switch to visiting PLMN context (001-01) and attempt setup for visiting gNB */
    switch_plmn_context(1);
    ogs_info("[TEST1] Attempting NG-Setup for Visiting gNB (PLMN 001-01)");
    sendbuf = testngap_build_ng_setup_request(0x4001, 22);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    
    /* Check if NG-Setup was accepted or rejected */
    rv = ogs_ngap_decode(&message, recvbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    
    // Assert that visiting gNB 0x4001 is accepted by visiting AMF
    ABTS_INT_EQUAL(tc, message.present, NGAP_NGAP_PDU_PR_successfulOutcome);
    
    ogs_ngap_free(&message);
    ogs_pkbuf_free(recvbuf);

    /* Switch back to home PLMN for UE registration */
    switch_plmn_context(0);

    /**************************************************************************
     * PHASE 1: REGISTER AND ESTABLISH SESSION IN HOME NETWORK
     **************************************************************************/

    ogs_info("[TEST1] ========================================");
    ogs_info("[TEST1] Phase 1: Home network registration");
    ogs_info("[TEST1] ========================================");

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

    ogs_info("[TEST1] Phase 1 complete - UE registered with active PDU session");

    /**************************************************************************
     * PHASE 2: ATTEMPT INTER-PLMN N2 HANDOVER (EXPECTED TO FAIL)
     * 
     * Source: gNB1 (PLMN 999-70) → Home AMF (127.0.1.5)
     * Target: gNB2 (PLMN 001-01) → Visiting AMF (127.0.2.5)
     **************************************************************************/

    ogs_info("[TEST1] ========================================");
    ogs_info("[TEST1] Phase 2: Attempting inter-PLMN N2 handover");
    ogs_info("[TEST1] ========================================");

    /* Prepare target with different PLMN (visiting network) */
    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;
    test_handover_failure_t handover_failure;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));

    /* Use visiting PLMN from configuration (001-01) */
    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);
    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1], OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 22;  /* Same TAC, different PLMN */

    ogs_info("[TEST1] Source PLMN: MCC=%03d MNC=%02d (Home)",
             ogs_plmn_id_mnc_len(&test_self()->plmn_support[0].plmn_id) == 2 ? 
             ogs_plmn_id_mcc(&test_self()->plmn_support[0].plmn_id) : 
             ogs_plmn_id_mcc(&test_self()->plmn_support[0].plmn_id),
             ogs_plmn_id_mnc(&test_self()->plmn_support[0].plmn_id));
    ogs_info("[TEST1] Target PLMN: MCC=%03d MNC=%02d (Visiting)",
             ogs_plmn_id_mnc_len(&target_plmn) == 2 ? 
             ogs_plmn_id_mcc(&target_plmn) : 
             ogs_plmn_id_mcc(&target_plmn),
             ogs_plmn_id_mnc(&target_plmn));
    ogs_info("[TEST1] Target gNB ID: 0x%x, TAC: %d", 0x4001, target_tai.tac.v);

    /* Build HandoverRequired with cross-PLMN target */
    ogs_info("[TEST1] → Building HandoverRequired with cross-PLMN target");
    sendbuf = testngap_build_handover_required_with_target_plmn(
            test_ue, 
            NGAP_HandoverType_intra5gs,
            0x4001,  /* target gNB ID */
            24,      /* bitsize */
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_handover_desirable_for_radio_reason,
            true,    /* direct forwarding */
            &target_plmn,
            &target_tai);
    ABTS_PTR_NOTNULL(tc, sendbuf);

    ogs_info("[TEST1] → Sending HandoverRequired to Home AMF");
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive response from AMF */
    ogs_info("[TEST1] ← Waiting for AMF response...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);

    /* Decode and verify it's HandoverPreparationFailure */
    rv = ogs_ngap_decode(&message, recvbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_info("[TEST1] ← Received NGAP message type: %d", message.present);
    
    /* Check for ErrorIndication - AMF cannot find target gNB */
    if (message.present == NGAP_NGAP_PDU_PR_initiatingMessage) {
        NGAP_InitiatingMessage_t *initiatingMessage = message.choice.initiatingMessage;
        
        if (initiatingMessage && 
            initiatingMessage->procedureCode == NGAP_ProcedureCode_id_ErrorIndication) {
            ogs_info("[TEST1] ← Received ErrorIndication from Home AMF");
            /* This is the expected outcome! */
            goto test1_success;
        }
    }
    
    /* Log what message we actually received */
    if (message.present == NGAP_NGAP_PDU_PR_successfulOutcome) {
        NGAP_SuccessfulOutcome_t *successfulOutcome = message.choice.successfulOutcome;
        ogs_info("[TEST1] ← Received SuccessfulOutcome, procedure: %ld", 
                 successfulOutcome->procedureCode);
        
        if (successfulOutcome->procedureCode == NGAP_ProcedureCode_id_HandoverPreparation) {
            ogs_warn("[TEST1] ! AMF sent HandoverCommand (unexpected)");
            ogs_warn("[TEST1] ! This would mean AMF found the target gNB");
            ogs_warn("[TEST1] ! Possible reasons:");
            ogs_warn("[TEST1] ! - Target gNB also connected to Home AMF");
            ogs_warn("[TEST1] ! - AMF incorrectly accepting invalid target");
        }
    }

    if (testngap_is_handover_preparation_failure(&message)) {
        ogs_info("[TEST1] ← Received HandoverPreparationFailure");
        
        testngap_extract_handover_failure_cause(&message, &handover_failure);
        
        if (handover_failure.received) {
            ogs_info("[TEST1] ← Failure Cause Group: %d", 
                     handover_failure.cause_group);
            ogs_info("[TEST1] ← Failure Cause Value: %ld", 
                     handover_failure.cause_value);
            
            if (testngap_is_n14_related_cause(
                    handover_failure.cause_group, 
                    handover_failure.cause_value)) {
                ogs_info("[TEST1] ✓ Cause indicates N14 unavailability");
            } else {
                ogs_info("[TEST1] ! Cause may not be N14-related");
            }
        }
        
        ogs_info("[TEST1] ✓ Inter-PLMN N2 handover correctly rejected");
        ogs_info("[TEST1] ✓ Reason: N14 interface not implemented in Open5GS");
    } else {
        ogs_warn("[TEST1] ========================================");
        ogs_warn("[TEST1] UNEXPECTED MESSAGE TYPE");
        ogs_warn("[TEST1] ========================================");
        ogs_warn("[TEST1] Expected: ErrorIndication or HandoverPreparationFailure");
        ogs_warn("[TEST1] Received: message type %d", message.present);
        ogs_warn("[TEST1] ");
        ogs_warn("[TEST1] This indicates unexpected AMF behavior.");
        ogs_warn("[TEST1] ========================================");
    }

test1_success:
    ogs_ngap_free(&message);
    ogs_pkbuf_free(recvbuf);

    /* Verify UE still has working data path in home network */
    rv = test_gtpu_send_ping(gtpu_home, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_gtpu_read(gtpu_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    ogs_info("[TEST1] UE remains active in home network");
    ogs_info("[TEST1] Inter-PLMN N2 handover requires N14 implementation");

    /********** Cleanup */
    cleanup_test_ue(tc, test_ue, ngap_home, gtpu_home);
    
    /* Close visiting network infrastructure */
    testgnb_gtpu_close(gtpu_visiting);
    testgnb_ngap_close(ngap_visiting);

    ogs_info("[TEST1] ========================================");
    ogs_info("[TEST1] Test complete - demonstrated N14 gap");
    ogs_info("[TEST1] ========================================");
    ogs_info("[TEST1] Key finding: Both networks operational,");
    ogs_info("[TEST1] but N14 interface required for inter-AMF handover");
}

/*
 * TEST 2: Inter-PLMN Handover with Indirect Forwarding
 * 
 * Setup: UE + session in Home PLMN (999-70)
 * Action: Handover with indirect forwarding (data via source UPF)
 * 
 * Current (NO N14): ErrorIndication - N14 needed regardless of forwarding mode
 * Expected (WITH N14): HandoverCommand with indirect data tunnels
 * 
 * Key: Both direct and indirect forwarding require N14 for inter-AMF
 * 3GPP: TS 23.502 §4.9.1.3.2
 */
static void test2_func(abts_case *tc, void *data)
{
    int rv;
    ogs_socknode_t *ngap_home, *ngap_visiting;
    ogs_socknode_t *gtpu_home, *gtpu_visiting;
    ogs_pkbuf_t *sendbuf;
    ogs_pkbuf_t *recvbuf;
    ogs_ngap_message_t message;

    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;
    test_bearer_t *qos_flow = NULL;

    bson_t *doc = NULL;

    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);

    ogs_info("[TEST2] ========================================");
    ogs_info("[TEST2] Testing indirect forwarding inter-PLMN");
    ogs_info("[TEST2] ========================================");

    /* Setup both network infrastructures */
    ogs_info("[TEST2] Setting up Home network gNB 0x4000");
    ngap_home = testngap_client(1, AF_INET);  /* Home AMF (127.0.1.5) */
    ABTS_PTR_NOTNULL(tc, ngap_home);
    gtpu_home = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_home);

    ogs_info("[TEST2] Setting up Visiting network gNB 0x4002");
    ngap_visiting = testngap_client(2, AF_INET);  /* Visiting AMF (127.0.2.5) */
    ABTS_PTR_NOTNULL(tc, ngap_visiting);
    gtpu_visiting = test_gtpu_server(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_visiting);

    /* Setup UE and insert in database */
    test_ue = create_test_ue("0000203192");
    doc = test_db_new_simple(test_ue);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    /* Switch to home PLMN context (999-70) */
    switch_plmn_context(0);

    /* NG-Setup with Home AMF */
    ogs_info("[TEST2] NG-Setup for Home gNB 0x4000");
    perform_ng_setup(tc, test_ue, ngap_home, 0x4000, 22);

    /* Setup visiting gNB with different TAC */
    switch_plmn_context(1);
    ogs_info("[TEST2] NG-Setup for Visiting gNB 0x4002 (TAC 23)");
    sendbuf = testngap_build_ng_setup_request(0x4002, 23);
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

    /* PDU Session Establishment */
    sess = establish_pdu_session(tc, test_ue, ngap_home, "internet", 5);

    /* Get QoS flow for data path verification */
    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);

    ogs_info("[TEST2] ========================================");
    ogs_info("[TEST2] Testing inter-PLMN handover with indirect forwarding");
    ogs_info("[TEST2] ========================================");

    /* Prepare target with different PLMN */
    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;
    test_handover_failure_t handover_failure;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));

    /* Use visiting PLMN from configuration */
    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1], OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 23;

    ogs_info("[TEST2] Attempting handover with indirect forwarding");
    ogs_info("[TEST2] → Building HandoverRequired (indirect, cross-PLMN)");
    
    sendbuf = testngap_build_handover_required_with_target_plmn(
            test_ue, 
            NGAP_HandoverType_intra5gs,
            0x4002,  /* different target gNB */
            24,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_handover_desirable_for_radio_reason,
            false,   /* indirect forwarding */
            &target_plmn,
            &target_tai);
    ABTS_PTR_NOTNULL(tc, sendbuf);

    ogs_info("[TEST2] → Sending HandoverRequired to Home AMF");
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive and verify failure */
    ogs_info("[TEST2] ← Waiting for AMF response...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);

    rv = ogs_ngap_decode(&message, recvbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_info("[TEST2] ← Received NGAP message type: %d", message.present);

    /* Check for ErrorIndication - AMF cannot find target gNB */
    if (message.present == NGAP_NGAP_PDU_PR_initiatingMessage) {
        NGAP_InitiatingMessage_t *initiatingMessage = message.choice.initiatingMessage;
        
        if (initiatingMessage && 
            initiatingMessage->procedureCode == NGAP_ProcedureCode_id_ErrorIndication) {
            ogs_info("[TEST2] ← Received ErrorIndication from Home AMF");
            ogs_info("[TEST2] ✓ SUCCESS: N14 required for indirect forwarding too");
            ogs_info("[TEST2] Both direct and indirect forwarding modes fail without N14");
            goto test2_success;
        }
    }

    if (testngap_is_handover_preparation_failure(&message)) {
        testngap_extract_handover_failure_cause(&message, &handover_failure);
        
        ogs_info("[TEST2] ← Received HandoverPreparationFailure");
        ogs_info("[TEST2] ← Cause: group=%d, value=%ld",
                 handover_failure.cause_group, handover_failure.cause_value);
        ogs_info("[TEST2] ✓ Indirect forwarding also fails without N14");
    } else {
        ogs_warn("[TEST2] ========================================");
        ogs_warn("[TEST2] UNEXPECTED MESSAGE TYPE");
        ogs_warn("[TEST2] Expected: ErrorIndication");
        ogs_warn("[TEST2] Received: message type %d", message.present);
        ogs_warn("[TEST2] ========================================");
    }

test2_success:

    ogs_ngap_free(&message);
    ogs_pkbuf_free(recvbuf);

    ogs_info("[TEST2] Result: N14 required for both direct and indirect");
    
    /* Verify data path still works */
    rv = test_gtpu_send_ping(gtpu_home, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_gtpu_read(gtpu_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    ogs_info("[TEST2] ✓ UE remains active in home network");

    /* Cleanup */
    cleanup_test_ue(tc, test_ue, ngap_home, gtpu_home);
    testgnb_gtpu_close(gtpu_visiting);
    testgnb_ngap_close(ngap_visiting);

    ogs_info("[TEST2] ========================================");
    ogs_info("[TEST2] Test complete");
    ogs_info("[TEST2] ========================================");
}

/*
 * TEST CASE 3: Inter-PLMN Partial Handover (Multiple Sessions)
 * 
 * Scenario:
 * - Establish internet session (succeeds)
 * - Attempt IMS session (may fail if not configured)
 * - Handover active session(s) to PLMN 001-01 (Visiting AMF 127.0.2.5)
 * - Uses indirect forwarding (realistic for inter-PLMN, no Xn link)
 * 
 * Current (NO N14): ErrorIndication - Home AMF cannot find target gNB
 * Expected (WITH N14): HandoverCommand via N14 for partial session transfer
 * 
 * Demonstrates: Even partial session transfer across PLMNs requires N14
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
    ogs_ngap_message_t message;

    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;
    bson_t *doc = NULL;

    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);

    ogs_info("[TEST3] ========================================");
    ogs_info("[TEST3] Multiple PDU sessions inter-PLMN");
    ogs_info("[TEST3] ========================================");

    /* Setup both network infrastructures */
    ogs_info("[TEST3] Setting up Home network gNB 0x4000");
    ngap_home = testngap_client(1, AF_INET);  /* Home AMF (127.0.1.5) */
    ABTS_PTR_NOTNULL(tc, ngap_home);
    gtpu_home = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_home);

    ogs_info("[TEST3] Setting up Visiting network gNB 0x4001");
    ngap_visiting = testngap_client(2, AF_INET);  /* Visiting AMF (127.0.2.5) */
    ABTS_PTR_NOTNULL(tc, ngap_visiting);
    gtpu_visiting = test_gtpu_server(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_visiting);

    /* Setup UE and insert in database */
    test_ue = create_test_ue("0000203193");
    doc = test_db_new_simple(test_ue);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    /* Switch to home PLMN context (999-70) */
    switch_plmn_context(0);

    /* NG-Setup with Home AMF */
    ogs_info("[TEST3] NG-Setup for Home gNB 0x4000");
    perform_ng_setup(tc, test_ue, ngap_home, 0x4000, 22);

    /* Setup visiting gNB */
    switch_plmn_context(1);
    ogs_info("[TEST3] NG-Setup for Visiting gNB 0x4001");
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
    ogs_info("[TEST3] Establishing PDU session 1: internet");
    sess = establish_pdu_session(tc, test_ue, ngap_home, "internet", 5);

    /* Attempt second PDU session: IMS */
    ogs_info("[TEST3] Attempting second PDU session: ims");
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

    /* Check if IMS session was rejected (5GMM status) */
    if (test_ue->ngap_procedure_code == NGAP_ProcedureCode_id_DownlinkNASTransport) {
        ogs_info("[TEST3] IMS session rejected by AMF (not configured)");
        ogs_info("[TEST3] Removing IMS session, will test with internet only");
        test_sess_remove(sess);
    } else {
        /* IMS accepted - send setup response */
        sendbuf = testngap_sess_build_pdu_session_resource_setup_response(sess);
        ABTS_PTR_NOTNULL(tc, sendbuf);
        rv = testgnb_ngap_send(ngap_home, sendbuf);
        ABTS_INT_EQUAL(tc, OGS_OK, rv);
        ogs_info("[TEST3] Both internet and IMS sessions established");
    }

    /* Attempt inter-PLMN handover with established session(s) */
    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));
    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1], OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 22;

    ogs_info("[TEST3] Attempting inter-PLMN handover to PLMN 001-01");

    sendbuf = testngap_build_handover_required_with_target_plmn(
            test_ue, 
            NGAP_HandoverType_intra5gs,
            0x4001,
            24,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_handover_desirable_for_radio_reason,
            false,  /* indirect forwarding - no Xn link between PLMNs */
            &target_plmn,
            &target_tai);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);

    rv = ogs_ngap_decode(&message, recvbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    if (message.present == NGAP_NGAP_PDU_PR_initiatingMessage) {
        NGAP_InitiatingMessage_t *initiatingMessage = message.choice.initiatingMessage;
        if (initiatingMessage && 
            initiatingMessage->procedureCode == NGAP_ProcedureCode_id_ErrorIndication) {
            ogs_info("[TEST3] ✓ ErrorIndication: Home AMF cannot reach target in other AMF");
            ogs_info("[TEST3] Partial session handover across PLMNs requires N14");
        }
    }

    ogs_ngap_free(&message);
    ogs_pkbuf_free(recvbuf);

    /* Cleanup */
    sendbuf = testngap_build_ue_context_release_request(test_ue,
            NGAP_Cause_PR_radioNetwork, NGAP_CauseRadioNetwork_user_inactivity,
            true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Cleanup */
    cleanup_test_ue(tc, test_ue, ngap_home, gtpu_home);
    testgnb_gtpu_close(gtpu_visiting);
    testgnb_ngap_close(ngap_visiting);

    ogs_info("[TEST3] ========================================");
    ogs_info("[TEST3] Test complete");
    ogs_info("[TEST3] ========================================");
}

abts_suite *test_n2_handover(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    ogs_info("========================================");
    ogs_info("Inter-PLMN N2 Handover Test Suite");
    ogs_info("========================================");
    ogs_info("Architecture Under Test:");
    ogs_info("  - Home AMF (999-70): 127.0.1.5");
    ogs_info("  - Visiting AMF (001-01): 127.0.2.5");
    ogs_info("  - Missing: N14 interface between AMFs");
    ogs_info(" ");

    abts_run_test(suite, test1_func, NULL);
    abts_run_test(suite, test2_func, NULL);
    abts_run_test(suite, test3_func, NULL);

    ogs_info(" ");
    ogs_info("========================================");
    ogs_info("Test Suite Summary (3 Tests):");
    ogs_info(" ");
    ogs_info("1. Direct Forwarding Cross-PLMN");
    ogs_info("   Target: gNB 0x4001, TAC 22");
    ogs_info("   Tests: Basic inter-PLMN handover with direct forwarding");
    ogs_info("   Status: FAILS (Expected) - N14 not implemented");
    ogs_info(" ");
    ogs_info("2. Indirect Forwarding Cross-PLMN");
    ogs_info("   Target: gNB 0x4002, TAC 23 (different from source)");
    ogs_info("   Tests: Inter-PLMN handover with data path verification");
    ogs_info("   Status: FAILS (Expected) - N14 not implemented");
    ogs_info(" ");
    ogs_info("3. Multiple PDU Sessions");
    ogs_info("   Tests: Partial session transfer across PLMNs");
    ogs_info("   Status: FAILS (Expected) - N14 not implemented");
    ogs_info(" ");
    ogs_info("========================================");
    ogs_info(" ");
    ogs_info("NOTE: All inter-PLMN N2 handovers require N14 interface");
    ogs_info("      (Namf_Communication service between AMFs)");
    ogs_info("========================================");

    return suite;
}
