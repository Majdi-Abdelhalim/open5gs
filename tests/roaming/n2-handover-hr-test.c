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
 * (V-SMF Insertion per TS 23.502 §4.9.1.3 + §4.23.7.3)
 *
 * Architecture Under Test:
 * - S-AMF / H-AMF: 127.0.1.5 (PLMN 999-70) — source, UE's home
 * - T-AMF / V-AMF: 127.0.2.5 (PLMN 001-01) — target, visited
 * - H-SMF: 127.0.1.4 (PLMN 999-70) — initially regular SMF, becomes H-SMF
 * - V-SMF (inserted): 127.0.2.4 (PLMN 001-01) — inserted during handover
 * - PSA UPF: 127.0.1.7 (PLMN 999-70) — PDU Session Anchor
 * - V-UPF (inserted): 127.0.2.7 (PLMN 001-01) — inserted during HO
 * - SEPP1 / SEPP2: inter-PLMN SBI routing
 *
 * KEY DIFFERENCE FROM LBO:
 * In LBO, PDU sessions are released/re-established.
 * In HR, PDU sessions are PRESERVED: V-SMF is inserted at the target PLMN,
 * which contacts the H-SMF anchor. The data path goes through V-UPF → PSA UPF.
 *
 * V-SMF INSERTION FLOW (§4.23.7.3):
 *   UE at HPLMN → VPLMN (no existing V-SMF):
 *   1. S-AMF → CreateUEContext → T-AMF (no SMF contact at source side)
 *   2. T-AMF selects V-SMF in visited PLMN
 *   3. T-AMF → V-SMF: CreateSMContext(PREPARING, h_smf_uri)
 *   4. V-SMF → H-SMF: Nsmf_PDUSession_Create(ho_preparation_indication)
 *   5. V-SMF selects V-UPF, establishes N4 session
 *   6. V-SMF responds to T-AMF with V-UPF N3 F-TEID
 *   7. T-AMF → HandoverRequest to target gNB (with V-UPF N3 tunnel)
 *   8. After HO Req Ack: V-SMF UpdateSMContext(PREPARED)
 *   9. After HO Notify: V-SMF UpdateSMContext(COMPLETED) → path switch
 *
 * Post-handover data path:
 *   UE → T-gNB → N3 → V-UPF (001-01) → N9 → PSA UPF (999-70) → DN
 *
 * RANStatusTransfer (TS 23.502 §4.23.7.3, between HandoverCommand and HandoverNotify):
 *   Test step 13: Source gNB → UplinkRANStatusTransfer → S-AMF
 *   Test step 14: S-AMF → N2InfoNotify(RAN_STATUS_TRANSFER) → T-AMF (server)
 *   Test step 15: T-AMF → DownlinkRANStatusTransfer → Target gNB
 *   Enables PDCP SN/HFN preservation for lossless in-sequence delivery.
 *
 * TEST COVERAGE:
 * 1. Basic home-routed inter-PLMN handover (single PDU session, V-SMF insertion)
 * 2. Indirect forwarding home-routed handover
 * 3. Multiple PDU sessions home-routed handover
 * 4. Handover cancellation with V-SMF rollback
 * 5. Handover failure with V-SMF rollback
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
 * Helper: Verify GTP-U data path works on the target network after handover.
 * Sends 2 IPv4 ICMP pings and verifies the responses are received.
 * Call this after handover completes to confirm the data plane is operational.
 *
 * @param gtpu:  GTP-U socket connected to the visiting/target UPF
 * @param sess:  Active session with valid QoS flow tunnel information
 * @param label: Test label for log messages (e.g. "TEST1", "HR-TEST2")
 */
static void verify_gtpu_post_handover(abts_case *tc,
        ogs_socknode_t *gtpu, test_sess_t *sess, const char *label)
{
    int rv;
    ogs_pkbuf_t *recvbuf;
    test_bearer_t *qos_flow;

    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);

    ogs_info("[%s] Verifying GTP-U data path post-handover in visiting network",
            label);

    /* Send first GTP-U ICMP ping */
    rv = test_gtpu_send_ping(gtpu, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP reply */
    recvbuf = testgnb_gtpu_read(gtpu);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    /* Send second GTP-U ICMP ping */
    rv = test_gtpu_send_ping(gtpu, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Receive GTP-U ICMP reply */
    recvbuf = testgnb_gtpu_read(gtpu);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    ogs_info("[%s] GTP-U data path verified - visiting network is operational",
            label);
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
     * PHASE 2: INTER-PLMN N2 HANDOVER WITH V-SMF INSERTION (§4.23.7.3)
     *
     * Source: gNB 0x4000 (PLMN 999-70) → S-AMF/H-AMF (127.0.1.5)
     * Target: gNB 0x4001 (PLMN 001-01) → T-AMF/V-AMF (127.0.2.5)
     *
     * V-SMF Insertion Flow (UE at HPLMN → VPLMN):
     *   1. Source gNB → HandoverRequired → S-AMF
     *   2. (server) S-AMF → CreateUEContext → T-AMF (NO SMF contact)
     *   3. (server) T-AMF → V-SMF: CreateSMContext(PREPARING, h_smf_uri)
     *   4. (server) V-SMF → H-SMF: Nsmf_PDUSession_Create(ho_preparation)
     *   5. (server) V-SMF: select V-UPF, N4 establishment
     *   6. (server) V-SMF → T-AMF: CreateSMContext resp (V-UPF N3 F-TEID)
     *   7. T-AMF → HandoverRequest (V-UPF N3 tunnel) → Target gNB
     *   8. Target gNB → HandoverRequestAck → T-AMF
     *   9. (server) T-AMF → V-SMF: UpdateSMContext(PREPARED)
     *  10. (server) V-SMF → H-SMF: forwarding tunnel setup
     *  11. (server) T-AMF → S-AMF: CreateUEContext 201 via SEPP
     *  12. S-AMF → HandoverCommand → Source gNB
     *  13. Source gNB → UplinkRANStatusTransfer → S-AMF
     *  14. (server) S-AMF → T-AMF: N2InfoNotify(RAN_STATUS_TRANSFER)
     *  15. T-AMF → DownlinkRANStatusTransfer → Target gNB
     *  16. Target gNB → HandoverNotify → T-AMF
     *  17. (server) T-AMF → S-AMF: N2InfoNotify(HANDOVER_COMPLETED)
     *  18. (server) T-AMF → V-SMF: UpdateSMContext(COMPLETED)
     *  19. (server) V-SMF → V-UPF: N4 Modification (DL to target gNB)
     *  20. (server) V-SMF → H-SMF: Update (switch N9 DL path)
     *  21. S-AMF → UEContextReleaseCommand → Source gNB
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

    /* Step 1: Send HandoverRequired to S-AMF (no SMF contact at source) */
    ogs_info("[HR-TEST1] Step 1: HandoverRequired → S-AMF");
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

    /* Step 7: Receive HandoverRequest on target gNB
     * V-SMF insertion: HandoverRequest includes PDUSessionResourceSetupListHOReq
     * with V-UPF's N3 F-TEID (from V-SMF CreateSMContext response).
     * Server-side: S-AMF→CreateUEContext→T-AMF→V-SMF→H-SMF chain completes. */
    ogs_info("[HR-TEST1] Step 7: ← Waiting for HandoverRequest...");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);
    ogs_info("[HR-TEST1] ← Received HandoverRequest (V-UPF N3 tunnel)");

    /* Save visiting AMF context */
    visiting_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;

    /* Step 8: Send HandoverRequestAck WITH PDU sessions
     * Target gNB allocates DL N3 F-TEID for each admitted session.
     * T-AMF will forward this to V-SMF via UpdateSMContext(PREPARED). */
    ogs_info("[HR-TEST1] Step 8: → HandoverRequestAck (with sessions)");
    sendbuf = testngap_build_handover_request_ack(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Save visiting ran_ue_ngap_id after ack builder incremented it */
    visiting_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /* Step 12: Receive HandoverCommand on source gNB
     * Server-side: T-AMF→V-SMF(PREPARED)→CreateUEContext 201→S-AMF.
     * S-AMF sends HandoverCommand to source gNB. */
    ogs_info("[HR-TEST1] Step 12: ← Waiting for HandoverCommand...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);
    ogs_info("[HR-TEST1] ← Received HandoverCommand");

    /* Step 13: Send UplinkRANStatusTransfer from source gNB to S-AMF
     * PDCP SN preservation for seamless handover.
     * Server-side: S-AMF → N2InfoNotify(RAN_STATUS_TRANSFER) → T-AMF */
    ogs_info("[HR-TEST1] Step 13: → UplinkRANStatusTransfer");
    sendbuf = testngap_build_uplink_ran_status_transfer(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Restore visiting AMF context for target-side messages */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;
    test_ue->nr_cgi.cell_id = 0x40011;

    /* Step 15: Receive DownlinkRANStatusTransfer on target gNB
     * T-AMF forwards the RANStatusTransfer to target gNB */
    ogs_info("[HR-TEST1] Step 15: ← DownlinkRANStatusTransfer");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_DownlinkRANStatusTransfer,
            test_ue->ngap_procedure_code);

    /* Step 16: Send HandoverNotify on target gNB */
    ogs_info("[HR-TEST1] Step 16: → HandoverNotify on visiting gNB");
    sendbuf = testngap_build_handover_notify(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Step 21: Receive UEContextReleaseCommand on source gNB
     * Server-side: T-AMF→S-AMF N2InfoNotify(HANDOVER_COMPLETED),
     * T-AMF→V-SMF UpdateSMContext(COMPLETED), V-SMF→V-UPF N4 mod,
     * V-SMF→H-SMF Update. S-AMF sends UEContextReleaseCommand. */
    ogs_info("[HR-TEST1] Step 21: ← Waiting for UEContextReleaseCommand...");
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

    /**************************************************************************
     * PHASE 3: VERIFY DATA PATH IN VISITING NETWORK (HR)
     * HR: PDU sessions are preserved via V-SMF insertion.
     * The V-UPF routes packets: target gNB → N3 → V-UPF → N9 → PSA UPF → DN.
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST1] ========================================");
    ogs_info("[HR-TEST1] Phase 3: Verify data path in visiting network");
    ogs_info("[HR-TEST1] ========================================");

    /* Switch to visiting AMF context for GTP-U verification */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;

    /* HR: verify preserved session via V-UPF → H-SMF → PSA UPF */
    verify_gtpu_post_handover(tc, gtpu_visiting, sess, "HR-TEST1");

    ogs_info("[HR-TEST1] Phase 3 complete - data path verified in visiting network");
    TIMING_PHASE_END("HR-TEST1", "Phase 3 (data path verification)", t_phase);

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
 * V-SMF insertion flow per §4.23.7.3.
 *
 * Setup:
 *   - UE + session in Home PLMN (999-70, gNB 0x4000)
 *   - Visiting gNB 0x4002, TAC 23
 *
 * 3GPP: TS 23.502 §4.9.1.3.2, §4.9.1.3.3, §4.23.7.3
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

    /* HandoverRequired with indirect forwarding (direct=false)
     * S-AMF sends CreateUEContext directly (no SMF contact at source) */
    ogs_info("[HR-TEST2] → HandoverRequired (indirect, cross-PLMN, V-SMF insertion)");
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

    /* Receive HandoverRequest on target gNB (with V-UPF N3 tunnel from V-SMF) */
    ogs_info("[HR-TEST2] ← Waiting for HandoverRequest (V-SMF insertion)...");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);

    visiting_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;

    /* HandoverRequestAck WITH sessions (V-SMF will receive PREPARED) */
    ogs_info("[HR-TEST2] → HandoverRequestAck (with sessions)");
    sendbuf = testngap_build_handover_request_ack(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    visiting_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /* Receive HandoverCommand on source gNB
     * Server: T-AMF→V-SMF(PREPARED)→CreateUEContext 201→S-AMF */
    ogs_info("[HR-TEST2] ← Waiting for HandoverCommand...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);

    /* UplinkRANStatusTransfer from source gNB to S-AMF */
    ogs_info("[HR-TEST2] → UplinkRANStatusTransfer");
    sendbuf = testngap_build_uplink_ran_status_transfer(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Restore visiting context for target-side messages */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;
    test_ue->nr_cgi.cell_id = 0x40021;

    /* DownlinkRANStatusTransfer on target gNB */
    ogs_info("[HR-TEST2] ← DownlinkRANStatusTransfer");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_DownlinkRANStatusTransfer,
            test_ue->ngap_procedure_code);

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

    /**************************************************************************
     * PHASE 3: VERIFY DATA PATH IN VISITING NETWORK (HR)
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST2] Phase 3: Verify data path in visiting network");

    /* Switch to visiting AMF context */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;

    /* HR: verify preserved session (PSI 5) via V-UPF */
    {
        test_sess_t *internet_sess = test_sess_find_by_psi(test_ue, 5);
        ogs_assert(internet_sess);
        verify_gtpu_post_handover(tc, gtpu_visiting, internet_sess, "HR-TEST2");
    }

    ogs_info("[HR-TEST2] Phase 3 complete - data path verified in visiting network");
    TIMING_PHASE_END("HR-TEST2", "Phase 3 (data path verification)", t_phase);

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
 * Action: Handover all active sessions together with V-SMF insertion.
 *
 * Expected: S-AMF sends CreateUEContext directly (no SMF contact),
 *   T-AMF selects V-SMF, V-SMF→H-SMF for each session,
 *   HandoverRequest with all sessions using V-UPF N3 tunnels.
 *
 * 3GPP: TS 23.502 §4.9.1.3.2, §4.23.7.3
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

    /* HandoverRequired (all HR sessions, V-SMF insertion for each) */
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

    /* HandoverRequest on target gNB (with V-UPF N3 tunnels from V-SMF) */
    ogs_info("[HR-TEST3] ← Waiting for HandoverRequest (V-SMF insertion)...");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);

    visiting_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;

    /* HandoverRequestAck WITH all sessions (V-SMF will receive PREPARED) */
    sendbuf = testngap_build_handover_request_ack(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    visiting_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /* HandoverCommand on source gNB
     * Server: T-AMF→V-SMF(PREPARED)→CreateUEContext 201→S-AMF */
    ogs_info("[HR-TEST3] ← Waiting for HandoverCommand...");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);

    /* UplinkRANStatusTransfer from source gNB */
    ogs_info("[HR-TEST3] → UplinkRANStatusTransfer");
    sendbuf = testngap_build_uplink_ran_status_transfer(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Restore visiting context */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;
    test_ue->nr_cgi.cell_id = 0x40011;

    /* DownlinkRANStatusTransfer on target gNB */
    ogs_info("[HR-TEST3] ← DownlinkRANStatusTransfer");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_DownlinkRANStatusTransfer,
            test_ue->ngap_procedure_code);

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

    /**************************************************************************
     * PHASE 3: VERIFY DATA PATH IN VISITING NETWORK (HR)
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST3] Phase 3: Verify data path in visiting network");

    /* Switch to visiting AMF context */
    test_ue->amf_ue_ngap_id = visiting_amf_ue_ngap_id;
    test_ue->ran_ue_ngap_id = visiting_ran_ue_ngap_id;

    /* HR: verify internet session (PSI 5) via V-UPF */
    {
        test_sess_t *internet_sess = test_sess_find_by_psi(test_ue, 5);
        ogs_assert(internet_sess);
        verify_gtpu_post_handover(tc, gtpu_visiting, internet_sess, "HR-TEST3");
    }

    ogs_info("[HR-TEST3] Phase 3 complete - data path verified in visiting network");
    TIMING_PHASE_END("HR-TEST3", "Phase 3 (data path verification)", t_phase);

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
 * TEST 4: Handover Cancel with V-SMF Insertion Rollback
 *
 * Setup: UE with home-routed session in Home PLMN (999-70)
 * Action: Start inter-PLMN HR handover with V-SMF insertion, then cancel
 *
 * V-SMF Insertion + Cancel Flow:
 *   1. Source gNB → HandoverRequired → S-AMF
 *   2. (server) S-AMF → CreateUEContext → T-AMF (no SMF contact)
 *   3. (server) T-AMF → V-SMF: CreateSMContext(PREPARING)
 *   4. (server) V-SMF → H-SMF: Create(ho_preparation_indication)
 *   5. T-AMF → HandoverRequest → Target gNB
 *   6. Target gNB → HandoverRequestAck → T-AMF
 *   7. (server) T-AMF → V-SMF: UpdateSMContext(PREPARED)
 *   8. (server) T-AMF → S-AMF: CreateUEContext 201
 *   9. S-AMF → HandoverCommand → Source gNB
 *  10. Source gNB → HandoverCancel → S-AMF
 *  11. S-AMF → HandoverCancelAcknowledge → Source gNB (immediate)
 *  12. (server) S-AMF notifies T-AMF, T-AMF → V-SMF: CANCELLED
 *  13. (server) V-SMF releases V-UPF, notifies H-SMF to revert
 *
 * Expected:
 *   - HandoverCancelAcknowledge received immediately on source gNB
 *   - V-SMF rolled back, V-UPF released
 *   - H-SMF reverts to non-roaming mode
 *   - UE remains registered on S-AMF
 *
 * 3GPP: TS 23.502 §4.9.1.3.3, §4.23.7.3
 */
static void test4_func(abts_case *tc, void *data)
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

    uint64_t visiting_amf_ue_ngap_id;
    uint32_t visiting_ran_ue_ngap_id;
    uint64_t home_amf_ue_ngap_id;
    uint32_t home_ran_ue_ngap_id;

    ogs_time_t t_total, t_phase;

    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);

    TIMING_PHASE_START(t_total);

    /**************************************************************************
     * PHASE 0: SETUP
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST4] ========================================");
    ogs_info("[HR-TEST4] Phase 0: Infrastructure setup");
    ogs_info("[HR-TEST4] ========================================");

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
    testngap_recv(test_ue, recvbuf);

    switch_plmn_context(0);

    TIMING_PHASE_END("HR-TEST4", "Phase 0 (setup)", t_phase);

    /**************************************************************************
     * PHASE 1: REGISTER AND ESTABLISH SESSION IN HOME NETWORK
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST4] ========================================");
    ogs_info("[HR-TEST4] Phase 1: Home network registration");
    ogs_info("[HR-TEST4] ========================================");

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

    TIMING_PHASE_END("HR-TEST4", "Phase 1 (registration)", t_phase);

    /**************************************************************************
     * PHASE 2: INTER-PLMN HR HANDOVER → CANCEL
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST4] ========================================");
    ogs_info("[HR-TEST4] Phase 2: Inter-PLMN HR handover + cancel");
    ogs_info("[HR-TEST4] ========================================");

    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));
    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1],
            OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 22;

    /* Step 1: HandoverRequired to S-AMF (no SMF contact at source) */
    ogs_info("[HR-TEST4] → HandoverRequired");
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

    /* Step 5: Receive HandoverRequest on target gNB (V-UPF N3 from V-SMF) */
    ogs_info("[HR-TEST4] ← HandoverRequest on visiting gNB (V-SMF insertion)");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);

    visiting_amf_ue_ngap_id = test_ue->amf_ue_ngap_id;

    /* Step 6: Send HandoverRequestAck WITH PDU sessions
     * T-AMF forwards to V-SMF as UpdateSMContext(PREPARED) */
    ogs_info("[HR-TEST4] → HandoverRequestAck (with sessions)");
    sendbuf = testngap_build_handover_request_ack(test_ue);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    visiting_ran_ue_ngap_id = test_ue->ran_ue_ngap_id;

    /* Step 9: Receive HandoverCommand on source gNB
     * Server: T-AMF→V-SMF(PREPARED)→CreateUEContext 201→S-AMF */
    ogs_info("[HR-TEST4] ← HandoverCommand on home gNB");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);

    /* IDs are now restored to Home AMF (from HandoverCommand message) */

    /* Step 10: Send HandoverCancel from source gNB
     * S-AMF will notify T-AMF, T-AMF→V-SMF(CANCELLED), V-UPF released */
    ogs_info("[HR-TEST4] → HandoverCancel");
    sendbuf = testngap_build_handover_cancel(test_ue,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_txnrelocoverall_expiry);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_home, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Step 11: Receive HandoverCancelAcknowledge immediately */
    ogs_info("[HR-TEST4] ← HandoverCancelAcknowledge (immediate)");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverCancel,
            test_ue->ngap_procedure_code);

    ogs_info("[HR-TEST4] ✓ HandoverCancelAcknowledge received");

    TIMING_PHASE_END("HR-TEST4", "Phase 2 (handover+cancel)", t_phase);

    /* Wait for V-SMF CANCELLED + V-UPF release + H-SMF revert in background */
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

    ogs_info("[HR-TEST4] ========================================");
    ogs_info("[HR-TEST4] Test complete - HR HandoverCancel OK");
    ogs_info("[HR-TEST4] ========================================");
    TIMING_TOTAL("HR-TEST4", t_total);
}

/*
 * TEST 5: Handover Failure with V-SMF Insertion Rollback
 *
 * Setup: UE with home-routed session in Home PLMN (999-70)
 * Action: Start inter-PLMN HR handover with V-SMF insertion,
 *         target gNB rejects HandoverRequest
 *
 * V-SMF Insertion + Failure Flow:
 *   1. Source gNB → HandoverRequired → S-AMF
 *   2. (server) S-AMF → CreateUEContext → T-AMF (no SMF contact)
 *   3. (server) T-AMF → V-SMF: CreateSMContext(PREPARING)
 *   4. (server) V-SMF → H-SMF: Create(ho_preparation_indication)
 *   5. T-AMF → HandoverRequest → Target gNB
 *   6. Target gNB → HandoverFailure → T-AMF
 *   7. (server) T-AMF → V-SMF: ReleaseSMContext
 *   8. (server) V-SMF releases V-UPF, notifies H-SMF to revert
 *   9. (server) T-AMF → S-AMF: CreateUEContext error (403)
 *  10. S-AMF → HandoverPreparationFailure → Source gNB
 *
 * Expected:
 *   - HandoverPreparationFailure received on source gNB
 *   - V-SMF rolled back, V-UPF released
 *   - H-SMF reverts to non-roaming mode
 *   - UE remains registered on S-AMF with existing sessions
 *
 * 3GPP: TS 23.502 §4.9.1.3.4, §4.23.7.3
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

    ogs_time_t t_total, t_phase;

    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id >= 2);

    TIMING_PHASE_START(t_total);

    /**************************************************************************
     * PHASE 0: SETUP
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST5] ========================================");
    ogs_info("[HR-TEST5] Phase 0: Infrastructure setup");
    ogs_info("[HR-TEST5] ========================================");

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

    TIMING_PHASE_END("HR-TEST5", "Phase 0 (setup)", t_phase);

    /**************************************************************************
     * PHASE 1: REGISTER AND ESTABLISH SESSION IN HOME NETWORK
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST5] ========================================");
    ogs_info("[HR-TEST5] Phase 1: Home network registration");
    ogs_info("[HR-TEST5] ========================================");

    perform_full_registration(tc, test_ue, ngap_home);
    sess = establish_pdu_session(tc, test_ue, ngap_home, "internet", 5);

    qos_flow = test_qos_flow_find_by_qfi(sess, 1);
    ogs_assert(qos_flow);

    rv = test_gtpu_send_ping(gtpu_home, qos_flow, TEST_PING_IPV4);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);
    recvbuf = testgnb_gtpu_read(gtpu_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    ogs_pkbuf_free(recvbuf);

    TIMING_PHASE_END("HR-TEST5", "Phase 1 (registration)", t_phase);

    /**************************************************************************
     * PHASE 2: INTER-PLMN HR HANDOVER → FAILURE
     **************************************************************************/

    TIMING_PHASE_START(t_phase);
    ogs_info("[HR-TEST5] ========================================");
    ogs_info("[HR-TEST5] Phase 2: Inter-PLMN HR handover + failure");
    ogs_info("[HR-TEST5] ========================================");

    ogs_plmn_id_t target_plmn;
    ogs_5gs_tai_t target_tai;

    memset(&target_plmn, 0, sizeof(target_plmn));
    memset(&target_tai, 0, sizeof(target_tai));
    memcpy(&target_plmn, &ogs_local_conf()->serving_plmn_id[1],
            OGS_PLMN_ID_LEN);
    memcpy(&target_tai.plmn_id, &target_plmn, OGS_PLMN_ID_LEN);
    target_tai.tac.v = 22;

    /* Step 1: HandoverRequired to S-AMF (no SMF contact at source) */
    ogs_info("[HR-TEST5] → HandoverRequired");
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

    /* Step 5: Receive HandoverRequest on target gNB (V-UPF N3 from V-SMF) */
    ogs_info("[HR-TEST5] ← HandoverRequest on visiting gNB (V-SMF insertion)");
    recvbuf = testgnb_ngap_read(ngap_visiting);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverResourceAllocation,
            test_ue->ngap_procedure_code);

    /* Step 6: Send HandoverFailure from target gNB
     * T-AMF will release V-SMF context, respond to S-AMF with error */
    ogs_info("[HR-TEST5] → HandoverFailure on visiting gNB");
    sendbuf = testngap_build_handover_failure(test_ue,
            NGAP_Cause_PR_radioNetwork,
            NGAP_CauseRadioNetwork_ho_target_not_allowed);
    ABTS_PTR_NOTNULL(tc, sendbuf);
    rv = testgnb_ngap_send(ngap_visiting, sendbuf);
    ABTS_INT_EQUAL(tc, OGS_OK, rv);

    /* Step 10: Receive HandoverPreparationFailure on source gNB
     * S-AMF receives error from T-AMF, sends failure to source gNB */
    ogs_info("[HR-TEST5] ← HandoverPreparationFailure on home gNB");
    recvbuf = testgnb_ngap_read(ngap_home);
    ABTS_PTR_NOTNULL(tc, recvbuf);
    testngap_recv(test_ue, recvbuf);
    ABTS_INT_EQUAL(tc, NGAP_ProcedureCode_id_HandoverPreparation,
            test_ue->ngap_procedure_code);

    ogs_info("[HR-TEST5] ✓ HandoverPreparationFailure received");

    TIMING_PHASE_END("HR-TEST5", "Phase 2 (handover+failure)", t_phase);

    /* Wait for V-SMF release + V-UPF cleanup + H-SMF revert in background */
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

    ogs_info("[HR-TEST5] ========================================");
    ogs_info("[HR-TEST5] Test complete - HR HandoverFailure OK");
    ogs_info("[HR-TEST5] ========================================");
    TIMING_TOTAL("HR-TEST5", t_total);
}

abts_suite *test_n2_handover_hr(abts_suite *suite)
{
    suite = ADD_SUITE(suite)

    ogs_info("========================================");
    ogs_info("Inter-PLMN N2 Handover HR Test Suite");
    ogs_info("  V-SMF Insertion per TS 23.502 §4.23.7.3");
    ogs_info("========================================");
    ogs_info("Architecture Under Test:");
    ogs_info("  - S-AMF/H-AMF (999-70): 127.0.1.5");
    ogs_info("  - T-AMF/V-AMF (001-01): 127.0.2.5");
    ogs_info("  - H-SMF (999-70): 127.0.1.4");
    ogs_info("  - V-SMF (001-01): 127.0.2.4 (inserted during HO)");
    ogs_info("  - PSA UPF (999-70): 127.0.1.7");
    ogs_info("  - V-UPF (001-01): 127.0.2.7 (inserted during HO)");
    ogs_info("  - N14 (Namf_Communication) between AMFs via SEPP");
    ogs_info("  - Home-Routed: V-SMF insertion + PDU session preservation");
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
    ogs_info("1. Basic HR Inter-PLMN Handover (V-SMF Insertion)");
    ogs_info("   Single PDU session, V-SMF insertion + RANStatusTransfer");
    ogs_info(" ");
    ogs_info("2. Indirect Forwarding HR (V-SMF Insertion)");
    ogs_info("   Inter-PLMN indirect (no direct Xn) + RANStatusTransfer");
    ogs_info(" ");
    ogs_info("3. Multiple PDU Sessions HR (V-SMF Insertion)");
    ogs_info("   All sessions via V-SMF insertion + RANStatusTransfer");
    ogs_info(" ");
    ogs_info("4. Handover Cancel (V-SMF Rollback)");
    ogs_info("   Source cancels, V-SMF+V-UPF released, H-SMF reverts");
    ogs_info(" ");
    ogs_info("5. Handover Failure (V-SMF Rollback)");
    ogs_info("   Target rejects, V-SMF+V-UPF released, H-SMF reverts");
    ogs_info(" ");
    ogs_info("========================================");

    return suite;
}
