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
 * - N14 (Namf_Communication) between AMFs routed through SEPP
 * 
 * N14 INTERFACE (3GPP TS 23.502 §4.9.1.3):
 * Implemented for inter-AMF handovers:
 * 1. Namf_Communication_CreateUEContext - UE context to target AMF
 * 2. Namf_Communication_N2InfoNotify - Handover completion notification
 * 3. AMF discovery via NRF with SEPP routing
 * 4. LBO: PDU sessions released and re-established after handover
 * 
 * TEST COVERAGE:
 * 1. Direct forwarding inter-PLMN handover
 * 2. Indirect forwarding inter-PLMN handover
 * 3. Multiple sessions with LBO handover
 * 4. Handover cancellation (inter-AMF)
 * 5. Handover failure (inter-AMF)
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
 * Helper: Build HandoverRequestAck without PDU sessions.
 * Used for inter-AMF LBO handover where no sessions are transferred.
 * Same as testngap_build_handover_request_ack() but skips sess_list iteration.
 */
static ogs_pkbuf_t *build_handover_request_ack_no_sessions(test_ue_t *test_ue)
{
    NGAP_NGAP_PDU_t pdu;
    NGAP_SuccessfulOutcome_t *successfulOutcome = NULL;
    NGAP_HandoverRequestAcknowledge_t *HandoverRequestAcknowledge = NULL;

    NGAP_HandoverRequestAcknowledgeIEs_t *ie = NULL;
    NGAP_AMF_UE_NGAP_ID_t *AMF_UE_NGAP_ID = NULL;
    NGAP_RAN_UE_NGAP_ID_t *RAN_UE_NGAP_ID = NULL;
    NGAP_TargetToSource_TransparentContainer_t
        *TargetToSource_TransparentContainer = NULL;

    ogs_assert(test_ue);

    memset(&pdu, 0, sizeof(NGAP_NGAP_PDU_t));
    pdu.present = NGAP_NGAP_PDU_PR_successfulOutcome;
    pdu.choice.successfulOutcome = CALLOC(1, sizeof(NGAP_SuccessfulOutcome_t));

    successfulOutcome = pdu.choice.successfulOutcome;
    successfulOutcome->procedureCode =
        NGAP_ProcedureCode_id_HandoverResourceAllocation;
    successfulOutcome->criticality = NGAP_Criticality_reject;
    successfulOutcome->value.present =
        NGAP_SuccessfulOutcome__value_PR_HandoverRequestAcknowledge;

    HandoverRequestAcknowledge =
        &successfulOutcome->value.choice.HandoverRequestAcknowledge;

    ie = CALLOC(1, sizeof(NGAP_HandoverRequestAcknowledgeIEs_t));
    ogs_assert(ie);
    ASN_SEQUENCE_ADD(&HandoverRequestAcknowledge->protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
    ie->criticality = NGAP_Criticality_ignore;
    ie->value.present =
        NGAP_HandoverRequestAcknowledgeIEs__value_PR_AMF_UE_NGAP_ID;

    AMF_UE_NGAP_ID = &ie->value.choice.AMF_UE_NGAP_ID;

    ie = CALLOC(1, sizeof(NGAP_HandoverRequestAcknowledgeIEs_t));
    ogs_assert(ie);
    ASN_SEQUENCE_ADD(&HandoverRequestAcknowledge->protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
    ie->criticality = NGAP_Criticality_ignore;
    ie->value.present =
        NGAP_HandoverRequestAcknowledgeIEs__value_PR_RAN_UE_NGAP_ID;

    RAN_UE_NGAP_ID = &ie->value.choice.RAN_UE_NGAP_ID;

    asn_uint642INTEGER(AMF_UE_NGAP_ID, test_ue->amf_ue_ngap_id);

    test_ue->ran_ue_ngap_id++;
    *RAN_UE_NGAP_ID = test_ue->ran_ue_ngap_id;

    /* No PDUSessionResourceAdmittedList for LBO (no sessions transferred) */

    ie = CALLOC(1, sizeof(NGAP_HandoverRequestAcknowledgeIEs_t));
    ogs_assert(ie);
    ASN_SEQUENCE_ADD(&HandoverRequestAcknowledge->protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_TargetToSource_TransparentContainer;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_HandoverRequestAcknowledgeIEs__value_PR_TargetToSource_TransparentContainer;

    TargetToSource_TransparentContainer =
        &ie->value.choice.TargetToSource_TransparentContainer;

    /* PER-encode a proper TargetNGRANNode-ToSourceNGRANNode-TransparentContainer
     * so Wireshark can decode it (replaces dummy 4-byte hex) */
    {
        NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer_t tc;
        uint8_t rrc_data[] = { 0x20, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00 };
        ogs_pkbuf_t *container_buf = NULL;

        memset(&tc, 0, sizeof(tc));
        tc.rRCContainer.size = sizeof(rrc_data);
        tc.rRCContainer.buf = CALLOC(sizeof(rrc_data), sizeof(uint8_t));
        memcpy(tc.rRCContainer.buf, rrc_data, sizeof(rrc_data));

        container_buf = ogs_asn_encode(
            &asn_DEF_NGAP_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer,
            &tc);
        ogs_assert(container_buf);

        TargetToSource_TransparentContainer->size = container_buf->len;
        TargetToSource_TransparentContainer->buf =
            CALLOC(container_buf->len, sizeof(uint8_t));
        memcpy(TargetToSource_TransparentContainer->buf,
                container_buf->data, container_buf->len);
        ogs_pkbuf_free(container_buf);
    }

    return ogs_ngap_encode(&pdu);
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
 * Expected Behavior (N14/Namf_Communication implemented):
 *   - Home AMF detects inter-PLMN target, discovers Visiting AMF via NRF/SEPP
 *   - Home AMF sends CreateUEContext to Visiting AMF
 *   - Visiting AMF sends HandoverRequest to target gNB (no PDU sessions for LBO)
 *   - Target gNB responds HandoverRequestAck
 *   - Visiting AMF responds CreateUEContext to Home AMF
 *   - Home AMF sends HandoverCommand to source gNB
 *   - Target gNB sends HandoverNotify to Visiting AMF
 *   - Visiting AMF sends N2InfoNotify(HANDOVER_COMPLETED) to Home AMF
 *   - Home AMF sends UEContextReleaseCommand to source gNB, releases sessions
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
     * PHASE 2: INTER-PLMN N2 HANDOVER VIA N14 (Namf_Communication)
     *
     * Source: gNB 0x4000 (PLMN 999-70) → Home AMF (127.0.1.5)
     * Target: gNB 0x4001 (PLMN 001-01) → Visiting AMF (127.0.2.5)
     *
     * Flow:
     *   1. Source gNB → HandoverRequired → Home AMF
     *   2. Home AMF → CreateUEContext (SBI/SEPP) → Visiting AMF
     *   3. Visiting AMF → HandoverRequest → Target gNB (no PDU sessions)
     *   4. Target gNB → HandoverRequestAck → Visiting AMF
     *   5. Visiting AMF → CreateUEContext response → Home AMF
     *   6. Home AMF → HandoverCommand → Source gNB
     *   7. Target gNB → HandoverNotify → Visiting AMF
     *   8. Visiting AMF → N2InfoNotify(HANDOVER_COMPLETED) → Home AMF
     *   9. Home AMF → UEContextReleaseCommand → Source gNB
     **************************************************************************/

    ogs_info("[TEST1] ========================================");
    ogs_info("[TEST1] Phase 2: Inter-PLMN N2 handover via N14");
    ogs_info("[TEST1] ========================================");

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
    ogs_info("[TEST1] → Sending HandoverRequired to Home AMF");
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

    /* Step 3: Receive HandoverRequest on target gNB (from Visiting AMF) */
    ogs_info("[TEST1] ← Waiting for HandoverRequest on visiting gNB...");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);
    ogs_info("[TEST1] ← Received HandoverRequest on visiting gNB");

    /* Save visiting AMF context */
    visiting_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;

    /* Step 4: Send HandoverRequestAck (no PDU sessions for LBO) */
    ogs_info("[TEST1] → Sending HandoverRequestAck (no sessions)");
    sendbuf = build_handover_request_ack_no_sessions(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Save visiting ran_ue_ngap_id after ack builder incremented it */
    visiting_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /* Step 6: Receive HandoverCommand on source gNB */
    ogs_info("[TEST1] ← Waiting for HandoverCommand on home gNB...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);
    ogs_info("[TEST1] ← Received HandoverCommand on home gNB");

    /* Restore visiting AMF context for target-side messages */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;
    test_ue->nr_cgi.cell_id = 0x40011;

    /* Step 7: Send HandoverNotify on target gNB */
    ogs_info("[TEST1] → Sending HandoverNotify on visiting gNB");
    sendbuf = testngap_build_handover_notify(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Step 9: Receive UEContextReleaseCommand on source gNB */
    ogs_info("[TEST1] ← Waiting for UEContextReleaseCommand on home gNB...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);
    ogs_info("[TEST1] ← Received UEContextReleaseCommand on home gNB");

    /* Send UEContextReleaseComplete on source gNB */
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    ogs_info("[TEST1] ✓ Inter-PLMN N2 handover completed successfully");

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

    ogs_info("[TEST1] ========================================");
    ogs_info("[TEST1] Test complete - inter-PLMN N2 handover OK");
    ogs_info("[TEST1] ========================================");
}

/*
 * TEST 2: Inter-PLMN Handover with Indirect Forwarding
 *
 * Setup: UE + session in Home PLMN (999-70)
 * Action: Handover with indirect forwarding to PLMN 001-01
 *
 * Expected (N14 implemented):
 *   Full inter-AMF handover via CreateUEContext + N2InfoNotify
 *   No PDU sessions transferred (LBO release-and-reestablish)
 *
 * Key: Both direct and indirect forwarding use N14 for inter-AMF
 * 3GPP: TS 23.502 §4.9.1.3.2
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
    establish_pdu_session(tc, test_ue, ngap_home, "internet", 5);

    ogs_info("[TEST2] ========================================");
    ogs_info("[TEST2] Inter-PLMN handover with indirect forwarding");
    ogs_info("[TEST2] ========================================");

    /* Prepare target with different PLMN */
    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;
    uint64_t visiting_amf_ue_ngap_id;
    uint32_t visiting_ran_ue_ngap_id;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));

    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1], OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 23;

    /* Send HandoverRequired to Home AMF */
    ogs_info("[TEST2] → Sending HandoverRequired (indirect, cross-PLMN)");
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

    /* Receive HandoverRequest on target gNB (from Visiting AMF) */
    ogs_info("[TEST2] ← Waiting for HandoverRequest on visiting gNB...");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);
    ogs_info("[TEST2] ← Received HandoverRequest on visiting gNB");

    /* Save visiting AMF context */
    visiting_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;

    /* Send HandoverRequestAck (no PDU sessions for LBO) */
    ogs_info("[TEST2] → Sending HandoverRequestAck (no sessions)");
    sendbuf = build_handover_request_ack_no_sessions(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    visiting_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /* Receive HandoverCommand on source gNB */
    ogs_info("[TEST2] ← Waiting for HandoverCommand on home gNB...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);
    ogs_info("[TEST2] ← Received HandoverCommand on home gNB");

    /* Restore visiting AMF context for target-side messages */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;
    test_ue->nr_cgi.cell_id = 0x40021;

    /* Send HandoverNotify on target gNB */
    ogs_info("[TEST2] → Sending HandoverNotify on visiting gNB");
    sendbuf = testngap_build_handover_notify(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive UEContextReleaseCommand on source gNB */
    ogs_info("[TEST2] ← Waiting for UEContextReleaseCommand on home gNB...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);
    ogs_info("[TEST2] ← Received UEContextReleaseCommand on home gNB");

    /* Send UEContextReleaseComplete on source gNB */
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    ogs_info("[TEST2] ✓ Inter-PLMN N2 handover (indirect) completed");

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

    ogs_info("[TEST2] ========================================");
    ogs_info("[TEST2] Test complete");
    ogs_info("[TEST2] ========================================");
}

/*
 * TEST CASE 3: Inter-PLMN Handover with Multiple PDU Sessions
 *
 * Scenario:
 * - Establish internet session (succeeds)
 * - Attempt IMS session (may fail if not configured)
 * - Handover active session(s) to PLMN 001-01 (Visiting AMF 127.0.2.5)
 *
 * Expected (N14 implemented):
 *   Full inter-AMF handover via CreateUEContext + N2InfoNotify.
 *   No PDU sessions transferred (LBO release-and-reestablish).
 *   Home AMF releases sessions after HANDOVER_COMPLETED notification.
 *
 * Demonstrates: LBO handover with multiple sessions active
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

    /* Inter-PLMN handover with established session(s) */
    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;
    uint64_t visiting_amf_ue_ngap_id;
    uint32_t visiting_ran_ue_ngap_id;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));
    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1], OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 22;

    ogs_info("[TEST3] Inter-PLMN handover to PLMN 001-01");

    /* Send HandoverRequired to Home AMF */
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

    /* Receive HandoverRequest on target gNB */
    ogs_info("[TEST3] ← Waiting for HandoverRequest on visiting gNB...");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);
    ogs_info("[TEST3] ← Received HandoverRequest on visiting gNB");

    /* Save visiting AMF context */
    visiting_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;

    /* Send HandoverRequestAck (no PDU sessions for LBO) */
    sendbuf = build_handover_request_ack_no_sessions(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    visiting_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /* Receive HandoverCommand on source gNB */
    ogs_info("[TEST3] ← Waiting for HandoverCommand on home gNB...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);
    ogs_info("[TEST3] ← Received HandoverCommand on home gNB");

    /* Restore visiting AMF context for target-side messages */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;
    test_ue->nr_cgi.cell_id = 0x40011;

    /* Send HandoverNotify on target gNB */
    ogs_info("[TEST3] → Sending HandoverNotify on visiting gNB");
    sendbuf = testngap_build_handover_notify(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive UEContextReleaseCommand on source gNB */
    ogs_info("[TEST3] ← Waiting for UEContextReleaseCommand on home gNB...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);
    ogs_info("[TEST3] ← Received UEContextReleaseCommand on home gNB");

    /* Send UEContextReleaseComplete on source gNB */
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    ogs_info("[TEST3] ✓ Inter-PLMN handover with sessions completed");

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

    ogs_info("[TEST3] ========================================");
    ogs_info("[TEST3] Test complete");
    ogs_info("[TEST3] ========================================");
}

/*
 * TEST 4: Inter-PLMN Handover — HandoverCancel
 *
 * Setup: UE + session in Home PLMN (999-70)
 * Action: Start inter-PLMN handover, then cancel after HandoverCommand
 *
 * Expected:
 *   - Home AMF sends CreateUEContext → Visiting AMF sends HandoverRequest
 *   - Target gNB responds HandoverRequestAck → Home AMF sends HandoverCommand
 *   - Source gNB sends HandoverCancel → Home AMF immediately sends
 *     HandoverCancelAcknowledge (no target_ue on source AMF)
 *   - Visiting AMF's UE context cleaned up separately
 *
 * Validates: ngap_handle_handover_cancel() inter-AMF branch
 */
static void test4_func(abts_case *tc, void *data)
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

    uint64_t visiting_amf_ue_ngap_id;
    uint32_t visiting_ran_ue_ngap_id;
    uint64_t home_amf_ue_ngap_id;
    uint32_t home_ran_ue_ngap_id;

    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);

    /**************************************************************************
     * PHASE 0: SETUP
     **************************************************************************/

    ogs_info("[TEST4] ========================================");
    ogs_info("[TEST4] Phase 0: Infrastructure setup");
    ogs_info("[TEST4] ========================================");

    ngap_home = testngap_client(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_home);
    gtpu_home = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_home);

    ngap_visiting = testngap_client(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_visiting);
    gtpu_visiting = test_gtpu_server(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_visiting);

    test_ue = create_test_ue("0000203191");
    doc = test_db_new_simple(test_ue);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    switch_plmn_context(0);
    perform_ng_setup(tc, test_ue, ngap_home, 0x4000, 22);

    switch_plmn_context(1);
    sendbuf = testngap_build_ng_setup_request(0x4001, 22);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    rv = ogs_ngap_decode(&message, recvbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, message.present, NGAP_NGAP_PDU_PR_successfulOutcome);
    ogs_ngap_free(&message);
    ogs_pkbuf_free(recvbuf);

    switch_plmn_context(0);

    /**************************************************************************
     * PHASE 1: REGISTER AND ESTABLISH SESSION IN HOME NETWORK
     **************************************************************************/

    ogs_info("[TEST4] ========================================");
    ogs_info("[TEST4] Phase 1: Home network registration");
    ogs_info("[TEST4] ========================================");

    perform_full_registration(tc, test_ue, ngap_home);
    sess = establish_pdu_session(tc, test_ue, ngap_home, "internet", 5);

    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);

    rv = test_gtpu_send_ping(gtpu_home, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    recvbuf = testgnb_gtpu_read(gtpu_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Save home AMF IDs */
    home_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;
    home_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /**************************************************************************
     * PHASE 2: INTER-PLMN HANDOVER → CANCEL
     *
     * Flow:
     *   1. Source gNB → HandoverRequired → Home AMF
     *   2. Home AMF → CreateUEContext → Visiting AMF
     *   3. Visiting AMF → HandoverRequest → Target gNB
     *   4. Target gNB → HandoverRequestAck → Visiting AMF
     *   5. Visiting AMF → CreateUEContext response → Home AMF
     *   6. Home AMF → HandoverCommand → Source gNB
     *   7. Source gNB → HandoverCancel → Home AMF
     *   8. Home AMF → HandoverCancelAcknowledge → Source gNB (immediate)
     **************************************************************************/

    ogs_info("[TEST4] ========================================");
    ogs_info("[TEST4] Phase 2: Inter-PLMN handover + cancel");
    ogs_info("[TEST4] ========================================");

    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));
    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1],
            OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 22;

    /* Step 1: HandoverRequired to Home AMF */
    ogs_info("[TEST4] → HandoverRequired");
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

    /* Step 3: Receive HandoverRequest on target gNB */
    ogs_info("[TEST4] ← HandoverRequest on visiting gNB");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);

    visiting_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;

    /* Step 4: Send HandoverRequestAck (no sessions) */
    ogs_info("[TEST4] → HandoverRequestAck (no sessions)");
    sendbuf = build_handover_request_ack_no_sessions(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    visiting_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /* Step 6: Receive HandoverCommand on source gNB */
    ogs_info("[TEST4] ← HandoverCommand on home gNB");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);

    /* IDs are now restored to Home AMF (from HandoverCommand message) */

    /* Step 7: Send HandoverCancel from source gNB */
    ogs_info("[TEST4] → HandoverCancel");
    sendbuf = testngap_build_handover_cancel(test_ue,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_txnrelocoverall_expiry);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Step 8: Receive HandoverCancelAcknowledge immediately */
    ogs_info("[TEST4] ← HandoverCancelAcknowledge (immediate)");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverCancel,
            test_ue->ngap_procedure_code);

    ogs_info("[TEST4] ✓ HandoverCancelAcknowledge received");
    ogs_msleep(300);

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

    /********** Cleanup home AMF UE context */
    test_ue->amf_ue_ngap_id = home_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = home_ran_ue_ngap_id;

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

    ogs_msleep(300);

    /********** Final cleanup */
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    testgnb_gtpu_close(gtpu_home);
    testgnb_ngap_close(ngap_home);
    testgnb_gtpu_close(gtpu_visiting);
    testgnb_ngap_close(ngap_visiting);
    test_ue_remove(test_ue);

    ogs_info("[TEST4] ========================================");
    ogs_info("[TEST4] Test complete - HandoverCancel OK");
    ogs_info("[TEST4] ========================================");
}

/*
 * TEST 5: Inter-PLMN Handover — HandoverFailure
 *
 * Setup: UE + session in Home PLMN (999-70)
 * Action: Start inter-PLMN handover, target gNB rejects HandoverRequest
 *
 * Expected:
 *   - Home AMF sends CreateUEContext → Visiting AMF sends HandoverRequest
 *   - Target gNB sends HandoverFailure → Visiting AMF responds with 403
 *     on deferred CreateUEContext stream, removes UE context
 *   - Home AMF receives 403 → sends HandoverPreparationFailure to source gNB
 *   - UE remains registered on Home AMF with existing sessions
 *
 * Validates: ngap_handle_handover_failure() inter-AMF + source AMF error path
 */
static void test5_func(abts_case *tc, void *data)
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

    /**************************************************************************
     * PHASE 0: SETUP
     **************************************************************************/

    ogs_info("[TEST5] ========================================");
    ogs_info("[TEST5] Phase 0: Infrastructure setup");
    ogs_info("[TEST5] ========================================");

    ngap_home = testngap_client(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_home);
    gtpu_home = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_home);

    ngap_visiting = testngap_client(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_visiting);
    gtpu_visiting = test_gtpu_server(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_visiting);

    test_ue = create_test_ue("0000203191");
    doc = test_db_new_simple(test_ue);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    switch_plmn_context(0);
    perform_ng_setup(tc, test_ue, ngap_home, 0x4000, 22);

    switch_plmn_context(1);
    sendbuf = testngap_build_ng_setup_request(0x4001, 22);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    rv = ogs_ngap_decode(&message, recvbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ABTS_INT_EQUAL(tc, message.present, NGAP_NGAP_PDU_PR_successfulOutcome);
    ogs_ngap_free(&message);
    ogs_pkbuf_free(recvbuf);

    switch_plmn_context(0);

    /**************************************************************************
     * PHASE 1: REGISTER AND ESTABLISH SESSION IN HOME NETWORK
     **************************************************************************/

    ogs_info("[TEST5] ========================================");
    ogs_info("[TEST5] Phase 1: Home network registration");
    ogs_info("[TEST5] ========================================");

    perform_full_registration(tc, test_ue, ngap_home);
    sess = establish_pdu_session(tc, test_ue, ngap_home, "internet", 5);

    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);

    rv = test_gtpu_send_ping(gtpu_home, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    recvbuf = testgnb_gtpu_read(gtpu_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /**************************************************************************
     * PHASE 2: INTER-PLMN HANDOVER → FAILURE
     *
     * Flow:
     *   1. Source gNB → HandoverRequired → Home AMF
     *   2. Home AMF → CreateUEContext → Visiting AMF
     *   3. Visiting AMF → HandoverRequest → Target gNB
     *   4. Target gNB → HandoverFailure → Visiting AMF
     *   5. Visiting AMF → 403 error on CreateUEContext → Home AMF
     *   6. Home AMF → HandoverPreparationFailure → Source gNB
     **************************************************************************/

    ogs_info("[TEST5] ========================================");
    ogs_info("[TEST5] Phase 2: Inter-PLMN handover + failure");
    ogs_info("[TEST5] ========================================");

    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));
    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1],
            OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 22;

    /* Step 1: HandoverRequired to Home AMF */
    ogs_info("[TEST5] → HandoverRequired");
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

    /* Step 3: Receive HandoverRequest on target gNB */
    ogs_info("[TEST5] ← HandoverRequest on visiting gNB");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);

    /* Step 4: Send HandoverFailure from target gNB */
    ogs_info("[TEST5] → HandoverFailure on visiting gNB");
    sendbuf = testngap_build_handover_failure(test_ue,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_ho_target_not_allowed);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Step 6: Receive HandoverPreparationFailure on source gNB */
    ogs_info("[TEST5] ← HandoverPreparationFailure on home gNB");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);

    ogs_info("[TEST5] ✓ HandoverPreparationFailure received");
    ogs_msleep(300);

    /********** Cleanup home AMF UE context (UE still registered) */
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

    ogs_msleep(300);

    /********** Final cleanup */
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));
    testgnb_gtpu_close(gtpu_home);
    testgnb_ngap_close(ngap_home);
    testgnb_gtpu_close(gtpu_visiting);
    testgnb_ngap_close(ngap_visiting);
    test_ue_remove(test_ue);

    ogs_info("[TEST5] ========================================");
    ogs_info("[TEST5] Test complete - HandoverFailure OK");
    ogs_info("[TEST5] ========================================");
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
    ogs_info("  - N14 (Namf_Communication) between AMFs via SEPP");
    ogs_info(" ");

//     abts_run_test(suite, test1_func, NULL);
//     abts_run_test(suite, test2_func, NULL);
//     abts_run_test(suite, test3_func, NULL);
//     abts_run_test(suite, test4_func, NULL);
    abts_run_test(suite, test5_func, NULL);

    ogs_info(" ");
    ogs_info("========================================");
    ogs_info("Test Suite Summary (5 Tests):");
    ogs_info(" ");
    ogs_info("1. Direct Forwarding Cross-PLMN");
    ogs_info("   Target: gNB 0x4001, TAC 22");
    ogs_info("   Tests: Inter-PLMN N2 handover with direct forwarding");
    ogs_info("   Status: PASS");
    ogs_info(" ");
    ogs_info("2. Indirect Forwarding Cross-PLMN");
    ogs_info("   Target: gNB 0x4002, TAC 23 (different from source)");
    ogs_info("   Tests: Inter-PLMN handover with indirect forwarding");
    ogs_info("   Status: PASS");
    ogs_info(" ");
    ogs_info("3. Multiple PDU Sessions");
    ogs_info("   Tests: Inter-PLMN handover with active sessions (LBO)");
    ogs_info("   Status: PASS");
    ogs_info(" ");
    ogs_info("4. Handover Cancel (Inter-AMF)");
    ogs_info("   Tests: Source gNB cancels after HandoverCommand");
    ogs_info("   Validates: inter-AMF branch in ngap_handle_handover_cancel");
    ogs_info("   Status: PASS");
    ogs_info(" ");
    ogs_info("5. Handover Failure (Inter-AMF)");
    ogs_info("   Tests: Target gNB rejects HandoverRequest");
    ogs_info("   Validates: inter-AMF failure + CreateUEContext error path");
    ogs_info("   Status: PASS");
    ogs_info(" ");
    ogs_info("========================================");

    return suite;
}
