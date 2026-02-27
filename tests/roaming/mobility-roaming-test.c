/*
 * Copyright (C) 2026 Eric Yan <qfyan@uwaterloo.ca>
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
 * Helper function to switch PLMN context for NG-Setup and NAS signaling.
 * This updates all PLMN-related fields that affect NG-Setup Request
 * and NAS message building.
 *
 * @param plmn_index: Index into ogs_local_conf()->serving_plmn_id[] array
 *                    0 = Home PLMN (999-70 from config)
 *                    1 = Visiting PLMN (001-01 from config)
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

static void test1_func(abts_case *tc, void *data)
{
    int rv;
    ogs_socknode_t *ngap_home;
    ogs_socknode_t *ngap_roaming;
    ogs_socknode_t *gtpu_home;
    ogs_socknode_t *gtpu_roaming;
    ogs_pkbuf_t *gmmbuf;
    ogs_pkbuf_t *gsmbuf;
    ogs_pkbuf_t *nasbuf;
    ogs_pkbuf_t *sendbuf;
    ogs_pkbuf_t *recvbuf;
    ogs_ngap_message_t message;
    int i;

    ogs_nas_5gs_mobile_identity_suci_t mobile_identity_suci;
    test_ue_t *test_ue = NULL;
    test_sess_t *sess = NULL;
    test_bearer_t *qos_flow = NULL;

    bson_t *doc = NULL;

    /* Timing variables */
    ogs_time_t test_start, phase1_start, phase1_end, phase2_start, phase2_end;
    ogs_time_t reg_start, reg_end, pdu_start, pdu_end;
    int64_t elapsed_usec;

    test_start = ogs_get_monotonic_time();

    /* 
     * Verify config has both PLMNs:
     *   serving_plmn_id[0] = Home PLMN (999-70)
     *   serving_plmn_id[1] = Visiting PLMN (001-01)
     * These are read from test.serving[] in gnb-999-70-ue-001-01.yaml
     */
    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);

    /* Setup Test UE & Session Context */
    memset(&mobile_identity_suci, 0, sizeof(mobile_identity_suci));

    mobile_identity_suci.h.supi_format = OGS_NAS_5GS_SUPI_FORMAT_IMSI;
    mobile_identity_suci.h.type = OGS_NAS_5GS_MOBILE_IDENTITY_SUCI;
    mobile_identity_suci.routing_indicator1 = 0;
    mobile_identity_suci.routing_indicator2 = 0xf;
    mobile_identity_suci.routing_indicator3 = 0xf;
    mobile_identity_suci.routing_indicator4 = 0xf;
    mobile_identity_suci.protection_scheme_id = OGS_PROTECTION_SCHEME_NULL;
    mobile_identity_suci.home_network_pki_value = 0;

    /*
     * SUCI Creation and Storage (3GPP TS 33.501 & TS 24.501):
     * 
     * In a real UE, SUCI would be generated on-demand by encrypting the SUPI
     * (IMSI) using the home network's public key. The UE can generate fresh
     * SUCI for enhanced privacy, but the SUPI remains constant.
     * 
     * IMPORTANT: Per 3GPP TS 24.501, the UE stores both SUCI and GUTI:
     * - SUCI: Derived from SUPI, used when GUTI not available or not recognized
     * - GUTI: Assigned by network, RETAINED even after deregistration
     * 
     * In this test framework:
     * - We create the SUCI structure once (line 109) and it persists in test_ue
     * - After home registration, test_ue will also store the assigned GUTI
     * - When roaming WITHOUT deregistration, UE sends GUTI (3GPP mobility behavior)
     * - If visiting AMF can't resolve GUTI, it requests SUCI via Identity procedure
     * 
     * protection_scheme_id = NULL means no encryption (test only - production
     * uses Scheme A/B with actual encryption). This allows us to see the
     * "SUCI" content (0000203190) in cleartext in logs.
     * 
     * Home PLMN is encoded in SUCI: MCC=999, MNC=70 (from mobile_identity_suci)
     */
    test_ue = test_ue_add_by_suci(&mobile_identity_suci, "0000203190");
    ogs_assert(test_ue);

    test_ue->nr_cgi.cell_id = 0x40001;

    test_ue->nas.registration.tsc = 0;
    test_ue->nas.registration.ksi = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    test_ue->nas.registration.follow_on_request = 1;
    test_ue->nas.registration.value = OGS_NAS_5GS_REGISTRATION_TYPE_INITIAL;

    test_ue->k_string = "465b5ce8b199b49faa5f0a2ee238a6bc";
    test_ue->opc_string = "e8ed289deba952e4283b54e88e6183ca";

    /* 
     * Set roaming mode from config (default: Home Routed).
     * Can be changed to test Local Breakout by setting:
     *   test.subscriber.lbo_roaming_allowed: true
     * in the config file.
     */
    test_ue->lbo_roaming_allowed = test_self()->default_lbo_roaming_allowed;

    /********** Insert Subscriber in Database */
    doc = test_db_new_simple(test_ue);
    ABTS_PTR_NOTNULL(tc, doc);
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_insert_ue(test_ue, doc));

    /**************************************************************************
     * PHASE 1: HOME NETWORK REGISTRATION (PLMN from config index 0)
     * Config: test.serving[0].plmn_id = 999-70 (Home)
     *         amf.ngap.server[0] = 127.0.1.5 (Home AMF)
     **************************************************************************/

    phase1_start = ogs_get_monotonic_time();
    ogs_info("[TIMING] Phase 1 (Home Network) started");

    /* Home gNB connects to Home AMF (from config: ngap_addr) */
    ngap_home = testngap_client(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_home);

    /* Home gNB connects to Home UPF */
    gtpu_home = test_gtpu_server(1, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_home);

    /* Switch to home PLMN context (index 0) for NG-Setup */
    switch_plmn_context(0);

    /* Send NG-Setup Request to Home AMF */
    sendbuf = testngap_build_ng_setup_request(0x4000, 22);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive NG-Setup Response from Home AMF */
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ogs_info("[TIMING] NG-Setup completed");

    /* Send Registration request in Home Network */
    reg_start = ogs_get_monotonic_time();
    
    /*
     * Mobile Identity in Registration Request (3GPP TS 23.502):
     * 
     * Per 3GPP, UE should attempt to use GUTI if available, otherwise SUCI.
     * Setting guti=1 means: "Use GUTI if test_ue has one, otherwise use SUCI"
     * 
     * For this INITIAL home registration, test_ue has NO prior GUTI yet,
     * so testgmm_build_registration_request() will automatically fall back
     * to using SUCI from test_ue->mobile_identity (created at line 109).
     * 
     * After this registration succeeds, the home AMF will assign a 5G-GUTI
     * which gets stored in test_ue->nas_5gs_guti. This GUTI will be used
     * in the roaming registration (Phase 2).
     */
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
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Identity request */
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send Identity response */
    gmmbuf = testgmm_build_identity_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Authentication request */
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send Authentication response */
    gmmbuf = testgmm_build_authentication_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive Security mode command */
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send Security mode complete */
    gmmbuf = testgmm_build_security_mode_complete(test_ue, nasbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive InitialContextSetupRequest + Registration accept */
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_InitialContextSetup,
            test_ue->ngap_procedure_code);

    /* Send UERadioCapabilityInfoIndication */
    sendbuf = testngap_build_ue_radio_capability_info_indication(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send InitialContextSetupResponse */
    sendbuf = testngap_build_initial_context_setup_response(test_ue, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send Registration complete */
    gmmbuf = testgmm_build_registration_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    reg_end = ogs_get_monotonic_time();
    elapsed_usec = (reg_end - reg_start);
    ogs_info("[TIMING] Home registration completed in %ld.%03ld ms",
             (long)(elapsed_usec / 1000), (long)(elapsed_usec % 1000));

    /* Receive Configuration update command */
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send PDU session establishment request in Home Network */
    pdu_start = ogs_get_monotonic_time();
    sess = test_sess_add_by_dnn_and_psi(test_ue, "internet", 5);
    ogs_assert(sess);

    sess->ul_nas_transport_param.request_type =
        OGS_NAS_5GS_REQUEST_TYPE_INITIAL;
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
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive PDUSessionResourceSetupRequest +
     * DL NAS transport +
     * PDU session establishment accept */
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_PDUSessionResourceSetup,
            test_ue->ngap_procedure_code);

    /* Send PDUSessionResourceSetupResponse */
    sendbuf = testngap_sess_build_pdu_session_resource_setup_response(sess);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    pdu_end = ogs_get_monotonic_time();
    elapsed_usec = (pdu_end - pdu_start);
    ogs_info("[TIMING] Home PDU session established in %ld.%03ld ms",
             (long)(elapsed_usec / 1000), (long)(elapsed_usec % 1000));

    /* Send GTP-U ICMP Packet in Home Network */
    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);
    rv = test_gtpu_send_ping(gtpu_home, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet in Home Network */
    recvbuf = testgnb_gtpu_read(gtpu_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Send GTP-U ICMP Packet */
    rv = test_gtpu_send_ping(gtpu_home, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet */
    recvbuf = testgnb_gtpu_read(gtpu_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Send GTP-U Router Solicitation */
    rv = test_gtpu_send_slacc_rs(gtpu_home, qos_flow);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U Router Advertisement */
    recvbuf = test_gtpu_read(gtpu_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testgtpu_recv(test_ue, recvbuf);

#if !defined(__FreeBSD__)
    /* Send GTP-U ICMP Packet */
    rv = test_gtpu_send_ping(gtpu_home, qos_flow, TEST_PING_IPV6);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet */
    recvbuf = test_gtpu_read(gtpu_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);
#endif

    /*
     * UE MOVES OUT OF RANGE (No Deregistration)
     * 
     * This simulates a realistic mobility scenario where the UE simply
     * moves out of coverage of the home network. In this case:
     * 
     * - NO explicit Deregistration Request is sent
     * - UE Context Release is triggered by radio inactivity
     * - UE retains its 5G-GUTI and security context (KAMF, NAS keys)
     * - Home AMF may keep UE context for a period (implementation-specific)
     * - When UE moves into visiting network, it performs Mobility Registration
     * - Visiting AMF receives Registration Request with home GUTI
     * 
     * This differs from explicit deregistration scenarios where:
     * - UE sends Deregistration Request (clean termination)
     * - AMF immediately releases all UE context
     * - Next registration is strictly "Initial" registration
     * 
     * The current test simulates loss of radio contact, which is more
     * realistic for cross-border roaming scenarios.
     */

    /* Send UEContextReleaseRequest (simulating radio link failure/UE moving away) */
    sendbuf = testngap_build_ue_context_release_request(test_ue,
            NGAP_Cause_PR_radioNetwork, NGAP_CauseRadioNetwork_user_inactivity,
            true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive UEContextReleaseCommand */
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);

    /* Send UEContextReleaseComplete */
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_info("[MOBILITY] UE moved out of range - home connection lost");
    ogs_msleep(300);

    /* Close Home gNB connections (UE out of range) */
    testgnb_gtpu_close(gtpu_home);
    testgnb_ngap_close(ngap_home);

    phase1_end = ogs_get_monotonic_time();
    elapsed_usec = (phase1_end - phase1_start);
    ogs_info("[TIMING] ========================================");
    ogs_info("[TIMING] Phase 1 (Home Network) completed in %ld.%03ld ms",
             (long)(elapsed_usec / 1000), (long)(elapsed_usec % 1000));
    ogs_info("[TIMING] ========================================");

    /* Remove session context from home network */
    test_sess_remove(sess);
    sess = NULL;
    qos_flow = NULL;

    /**************************************************************************
     * PHASE 2: ROAMING NETWORK REGISTRATION (PLMN from config index 1)
     * Config: test.serving[1].plmn_id = 001-01 (Visiting)
     *         amf.ngap.server[1] = 127.0.2.5 (Visiting AMF)
     *
     * MOBILITY REGISTRATION WITHOUT DEREGISTRATION (3GPP TS 23.502):
     * 
     * This test simulates the realistic scenario where a UE moves from home
     * network coverage into visiting network coverage without explicit
     * deregistration. This represents true mobility/roaming behavior:
     * 
     * UE State After Moving Out of Home Network:
     * - 5G-GUTI from home AMF is RETAINED (per 3GPP TS 24.501)
     * - Security context (KAMF, NAS keys) is RETAINED
     * - UE considers itself "registered" but has no radio connection
     * - UE performs periodic PLMN searches and finds visiting network
     * 
     * Registration Type (3GPP TS 23.502 Section 4.2.2.2):
     * - UE sends Registration Request with 5G-GUTI and type=MOBILITY_UPDATING
     * - This indicates: "I was registered elsewhere, now moving to this AMF"
     * - Visiting AMF examines GUTI, recognizes it's from foreign AMF
     * 
     * N14 (Namf_Communication_CreateUEContext/N2InfoNotify) is implemented
     * for inter-PLMN N2 handover — see n2-handover-lbo-test.c and
     * n2-handover-hr-test.c for those test cases.
     *
     * This test exercises the mobility re-registration path (no handover):
     * visiting AMF receives a foreign GUTI it cannot resolve, sends an
     * Identity Request, and proceeds with full authentication via SEPP.
     * Session continuity is not preserved (new PDU session established).
     **************************************************************************/

    phase2_start = ogs_get_monotonic_time();
    ogs_info("[TIMING] Phase 2 (Roaming Network) started");
    ogs_info("[MOBILITY] UE detected visiting network, initiating registration");

    /* Roaming gNB connects to Visiting AMF (from config: ngap2_addr) */
    ngap_roaming = testngap_client(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, ngap_roaming);

    /* Roaming gNB connects to Visiting UPF */
    gtpu_roaming = test_gtpu_server(2, AF_INET);
    ABTS_PTR_NOTNULL(tc, gtpu_roaming);

    /* Switch to visiting PLMN context (index 1) for NG-Setup */
    switch_plmn_context(1);

    /* Send NG-Setup Request to Visiting AMF */
    sendbuf = testngap_build_ng_setup_request(0x4001, 22);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive NG-Setup Response from Visiting AMF */
    recvbuf = testgnb_ngap_read(ngap_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ogs_info("[TIMING] Roaming NG-Setup completed");

    /* Reset NGAP IDs for new connection to roaming AMF */
    test_ue->ran_ue_ngap_id = 0;
    test_ue->amf_ue_ngap_id = 0;

    /*
     * IMPORTANT: Security context and GUTI are NOT reset
     * 
     * Unlike the simple-roaming-test which includes explicit deregistration,
     * this test simulates real mobility where the UE retains:
     * - Its 5G-GUTI from home network
     * - Its security context (KAMF, KSI)
     * - Its registration state (considers itself registered)
     * 
     * However, for this specific test we reset the security context to force
     * fresh authentication (this test exercises the full re-registration path;
     * N2 inter-PLMN handover with context preservation is tested in
     * n2-handover-lbo-test.c and n2-handover-hr-test.c).
     */
    test_ue->nas.registration.tsc = 0;
    test_ue->nas.registration.ksi = OGS_NAS_KSI_NO_KEY_IS_AVAILABLE;
    
    /* Use INITIAL registration to exercise the full re-registration path.
     * A real UE retaining its GUTI would send MOBILITY_UPDATING here, but
     * for this test we focus on the clean registration flow, not handover.
     * Inter-PLMN N2 handover with context preservation is tested in
     * n2-handover-lbo-test.c and n2-handover-hr-test.c. */
    test_ue->nas.registration.value = OGS_NAS_5GS_REGISTRATION_TYPE_INITIAL;

    /* Reset all registration request parameters */
    memset(&test_ue->registration_request_param, 0, 
           sizeof(test_ue->registration_request_param));

    /* Update UE location - now in roaming network cell */
    test_ue->nr_cgi.cell_id = 0x40002;
    memcpy(&test_ue->nr_cgi.plmn_id, &test_self()->nr_tai.plmn_id,
            OGS_PLMN_ID_LEN);
    memcpy(&test_ue->nr_tai.plmn_id, &test_self()->nr_tai.plmn_id,
            OGS_PLMN_ID_LEN);

    /* Send Registration request in Roaming Network */
    reg_start = ogs_get_monotonic_time();
    
    /*
     * Mobile Identity in Mobility Registration (3GPP TS 24.501):
     * 
     * Per 3GPP TS 24.501 Section 5.5.1.2.2:
     * "If the UE holds a valid 5G-GUTI, the UE shall include the 5G-GUTI
     *  in the 5GS mobile identity IE"
     * 
     * The UE did NOT deregister from the home network - it simply moved
     * out of range. Therefore, it still has a valid 5G-GUTI from the
     * home AMF and MUST include it in the Registration Request.
     * 
     * Setting guti=1 instructs the test framework to use the stored GUTI.
     * Since test_ue->nas_5gs_guti was populated during Phase 1 home
     * registration, the message builder will use that GUTI.
     * 
     * What happens next (mobility re-registration scenario):
     * 1. Visiting AMF receives foreign GUTI
     * 2. Cannot resolve it (no UEContextTransfer for this scenario)
     * 3. Sends Identity Request to obtain SUCI
     * 4. Proceeds with full authentication via SEPP
     */
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
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ogs_info("[TIMING] Roaming registration request sent (with home GUTI)");

    /*
     * Identity Exchange (foreign GUTI not resolved):
     *
     * The visiting AMF receives a Registration Request with a 5G-GUTI from
     * the home network. Per 3GPP TS 23.502: "If the SUCI is not provided by
     * the UE nor retrieved from the old AMF, the Identity Request procedure
     * is initiated by AMF". The visiting AMF sends Identity Request and UE
     * responds with SUCI, then full authentication proceeds via SEPP.
     */

    /* Receive Identity request */
    recvbuf = testgnb_ngap_read(ngap_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ogs_info("[TIMING] Identity request received (foreign GUTI, visiting AMF sends Identity Request)");

    /* Send Identity response */
    gmmbuf = testgmm_build_identity_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ogs_info("[TIMING] Identity response sent");

    /* Receive Authentication request (routed via SEPP to home network) */
    recvbuf = testgnb_ngap_read(ngap_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ogs_info("[TIMING] Authentication request received (via SEPP)");

    /* Send Authentication response */
    gmmbuf = testgmm_build_authentication_response(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ogs_info("[TIMING] Authentication response sent (via SEPP)");

    /* Receive Security mode command */
    recvbuf = testgnb_ngap_read(ngap_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ogs_info("[TIMING] Security mode command received");

    /* Send Security mode complete */
    gmmbuf = testgmm_build_security_mode_complete(test_ue, nasbuf);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    ogs_info("[TIMING] Security mode complete sent");

    /* Receive InitialContextSetupRequest + Registration accept */
    recvbuf = testgnb_ngap_read(ngap_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_InitialContextSetup,
            test_ue->ngap_procedure_code);
    ogs_info("[TIMING] InitialContextSetupRequest received");

    /* Send UERadioCapabilityInfoIndication */
    sendbuf = testngap_build_ue_radio_capability_info_indication(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send InitialContextSetupResponse */
    sendbuf = testngap_build_initial_context_setup_response(test_ue, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send Registration complete */
    gmmbuf = testgmm_build_registration_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_uplink_nas_transport(test_ue, gmmbuf);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    reg_end = ogs_get_monotonic_time();
    elapsed_usec = (reg_end - reg_start);
    ogs_info("[TIMING] Roaming registration completed in %ld.%03ld ms",
             (long)(elapsed_usec / 1000), (long)(elapsed_usec % 1000));

    /* Receive Configuration update command */
    recvbuf = testgnb_ngap_read(ngap_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);

    /* Send PDU session establishment request in Roaming Network */
    pdu_start = ogs_get_monotonic_time();
    sess = test_sess_add_by_dnn_and_psi(test_ue, "internet", 6);
    ogs_assert(sess);

    /* Set gNB GTP-U address to gnb2 (127.0.0.3) for roaming network */
    sess->gnb_n3_addr = test_self()->gnb2_addr;
    sess->gnb_n3_addr6 = test_self()->gnb2_addr6;

    sess->ul_nas_transport_param.request_type =
        OGS_NAS_5GS_REQUEST_TYPE_INITIAL;
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
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive PDUSessionResourceSetupRequest +
     * DL NAS transport +
     * PDU session establishment accept */
    recvbuf = testgnb_ngap_read(ngap_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_PDUSessionResourceSetup,
            test_ue->ngap_procedure_code);

    /* Send PDUSessionResourceSetupResponse */
    sendbuf = testngap_sess_build_pdu_session_resource_setup_response(sess);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    pdu_end = ogs_get_monotonic_time();
    elapsed_usec = (pdu_end - pdu_start);
    ogs_info("[TIMING] Roaming PDU session established in %ld.%03ld ms",
             (long)(elapsed_usec / 1000), (long)(elapsed_usec % 1000));

    /* Send GTP-U ICMP Packet in Roaming Network */
    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);
    rv = test_gtpu_send_ping(gtpu_roaming, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet */
    recvbuf = testgnb_gtpu_read(gtpu_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Send GTP-U ICMP Packet */
    rv = test_gtpu_send_ping(gtpu_roaming, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet */
    recvbuf = testgnb_gtpu_read(gtpu_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Send GTP-U Router Solicitation */
    rv = test_gtpu_send_slacc_rs(gtpu_roaming, qos_flow);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U Router Advertisement */
    recvbuf = test_gtpu_read(gtpu_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testgtpu_recv(test_ue, recvbuf);

#if !defined(__FreeBSD__)
    /* Send GTP-U ICMP Packet */
    rv = test_gtpu_send_ping(gtpu_roaming, qos_flow, TEST_PING_IPV6);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP Packet */
    recvbuf = test_gtpu_read(gtpu_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);
#endif

    /* Send UEContextReleaseRequest in Roaming Network */
    sendbuf = testngap_build_ue_context_release_request(test_ue,
            NGAP_Cause_PR_radioNetwork, NGAP_CauseRadioNetwork_user_inactivity,
            true);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive UEContextReleaseCommand */
    recvbuf = testgnb_ngap_read(ngap_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);

    /* Send UEContextReleaseComplete */
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Send De-registration request in Roaming Network */
    gmmbuf = testgmm_build_de_registration_request(test_ue, 1, true, false);
    ABTS_PTR_NOTNULL(tc, gmmbuf);
    sendbuf = testngap_build_initial_ue_message(test_ue, gmmbuf,
                NGAP_RRCEstablishmentCause_mo_Signalling, true, false);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive UEContextReleaseCommand */
    recvbuf = testgnb_ngap_read(ngap_roaming);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc,
            NGAP_ProcedureCode_id_UEContextRelease,
            test_ue->ngap_procedure_code);

    /* Send UEContextReleaseComplete */
    sendbuf = testngap_build_ue_context_release_complete(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_roaming, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    ogs_msleep(300);

    phase2_end = ogs_get_monotonic_time();
    elapsed_usec = (phase2_end - phase2_start);
    ogs_info("[TIMING] ========================================");
    ogs_info("[TIMING] Phase 2 (Roaming Network) completed in %ld.%03ld ms",
             (long)(elapsed_usec / 1000), (long)(elapsed_usec % 1000));
    ogs_info("[TIMING] ========================================");

    /* Print overall test summary */
    elapsed_usec = (phase2_end - test_start);
    ogs_info("[TIMING] ****************************************");
    ogs_info("[TIMING] TOTAL TEST TIME: %ld.%03ld ms",
             (long)(elapsed_usec / 1000), (long)(elapsed_usec % 1000));
    ogs_info("[TIMING] ****************************************");

    /********** Remove Subscriber in Database */
    ABTS_INT_EQUAL(tc, OGS_OK, test_db_remove_ue(test_ue));

    /* Close Roaming gNB connections */
    testgnb_gtpu_close(gtpu_roaming);
    testgnb_ngap_close(ngap_roaming);

    /* Clear Test UE Context */
    test_ue_remove(test_ue);
}

abts_suite *test_mobility_roaming(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    abts_run_test(suite, test1_func, NULL);

    return suite;
}
