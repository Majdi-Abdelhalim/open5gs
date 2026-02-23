/*
 * Copyright (C) 2019-2025 by Sukchan Lee <acetcom@gmail.com>
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

#include "namf-build.h"
#include "namf-handler.h"
#include "nsmf-build.h"

#include "openapi/model/n2_information_notification.h"

static char* ogs_guti_to_string(ogs_nas_5gs_guti_t *nas_guti)
{
    ogs_plmn_id_t plmn_id;
    char plmn_id_buff[OGS_PLMNIDSTRLEN];
    char *amf_id = NULL;
    char *tmsi = NULL;
    char *guti = NULL;

    ogs_assert(nas_guti);

    memset(&plmn_id, 0, sizeof(plmn_id));
    ogs_nas_to_plmn_id(&plmn_id, &nas_guti->nas_plmn_id);
    amf_id = ogs_amf_id_to_string(&nas_guti->amf_id);
    tmsi = ogs_uint32_to_0string(nas_guti->m_tmsi);

    guti = ogs_msprintf("5g-guti-%s%s%s",
            ogs_plmn_id_to_string(&plmn_id, plmn_id_buff),
            amf_id,
            tmsi);

    /* TS29.518 6.1.3.2.2 Guti pattern (27 or 28 characters):
    "5g-guti-[0-9]{5,6}[0-9a-fA-F]{14}" */
    ogs_assert(strlen(guti) == (OGS_MAX_5G_GUTI_LEN - 1) ||
            (strlen(guti)) == OGS_MAX_5G_GUTI_LEN);

    ogs_free(amf_id);
    ogs_free(tmsi);

    return guti;
}

static char* amf_ue_to_context_id(amf_ue_t *amf_ue)
{
    char *ue_context_id = NULL;

    if (amf_ue->supi) {
        ue_context_id = ogs_strdup(amf_ue->supi);
    } else {
        ue_context_id = ogs_guti_to_string(&amf_ue->old_guti);
    }

    return ue_context_id;
}

ogs_sbi_request_t *amf_namf_comm_build_ue_context_transfer(
        amf_ue_t *amf_ue, void *data)
{
    ogs_sbi_message_t message;
    ogs_sbi_request_t *request = NULL;
    OpenAPI_ue_context_transfer_req_data_t UeContextTransferReqData;
    char *ue_context_id = NULL;

    ogs_assert(amf_ue);

    ue_context_id = amf_ue_to_context_id(amf_ue);
    ogs_assert(ue_context_id);

    memset(&UeContextTransferReqData, 0, sizeof(UeContextTransferReqData));
    UeContextTransferReqData.access_type = amf_ue->nas.access_type;
    UeContextTransferReqData.reason = amf_ue->nas.registration.value;

    memset(&message, 0, sizeof(message));
    message.h.method = (char *)OGS_SBI_HTTP_METHOD_POST;
    message.h.service.name = (char *)OGS_SBI_SERVICE_NAME_NAMF_COMM;
    message.h.api.version = (char *)OGS_SBI_API_V1;
    message.h.resource.component[0] = (char *)OGS_SBI_RESOURCE_NAME_UE_CONTEXTS;
    message.h.resource.component[1] = ue_context_id;
    message.h.resource.component[2] = (char *)OGS_SBI_RESOURCE_NAME_TRANSFER;
    message.UeContextTransferReqData = &UeContextTransferReqData;

    request = ogs_sbi_build_request(&message);
    ogs_expect(request);

    if (ue_context_id)
        ogs_free(ue_context_id);

    return request;
}

ogs_sbi_request_t *amf_namf_comm_build_create_ue_context(
        amf_ue_t *amf_ue, void *data)
{
    ogs_sbi_message_t message;
    ogs_sbi_request_t *request = NULL;
    ogs_sbi_server_t *server = NULL;
    ogs_sbi_header_t header;

    OpenAPI_ue_context_create_data_t UeContextCreateData;
    OpenAPI_ue_context_t UeContext;
    OpenAPI_n2_info_content_t sourceToTargetData;
    OpenAPI_ref_to_binary_data_t ngapData;
    OpenAPI_ng_ap_cause_t NgapCause;
    OpenAPI_plmn_id_nid_t ServingNetwork;
    OpenAPI_plmn_id_t *serving_plmn_id = NULL;

    OpenAPI_seaf_data_t SeafData;
    OpenAPI_ng_ksi_t Ng_ksi;
    OpenAPI_key_amf_t Key_amf;
    OpenAPI_ambr_t *UeAmbr = NULL;
    OpenAPI_list_t *MmContextList = NULL;
    char *encoded_gmm_capability = NULL;
    char hxkamf_string[OGS_KEYSTRLEN(OGS_SHA256_DIGEST_SIZE)];
    char hxnh_string[OGS_KEYSTRLEN(OGS_SHA256_DIGEST_SIZE)];

    OpenAPI_ng_ran_target_id_t *targetId = NULL;
    NGAP_TargetID_t *TargetID = NULL;

    char *ue_context_id = NULL;
    ogs_pkbuf_t *container_pkbuf = NULL;

    ogs_assert(amf_ue);
    ogs_assert(amf_ue->supi);

    TargetID = (NGAP_TargetID_t *)data;
    ogs_assert(TargetID);

    ue_context_id = amf_ue_to_context_id(amf_ue);
    ogs_assert(ue_context_id);

    /* Build OpenAPI target_id from NGAP TargetID */
    targetId = amf_nsmf_pdusession_build_target_id(TargetID);
    if (!targetId) {
        ogs_error("Failed to build target_id");
        ogs_free(ue_context_id);
        return NULL;
    }

    memset(&message, 0, sizeof(message));
    message.h.method = (char *)OGS_SBI_HTTP_METHOD_POST;
    message.h.service.name = (char *)OGS_SBI_SERVICE_NAME_NAMF_COMM;
    message.h.api.version = (char *)OGS_SBI_API_V1;
    message.h.resource.component[0] =
            (char *)OGS_SBI_RESOURCE_NAME_UE_CONTEXTS;
    message.h.resource.component[1] = ue_context_id;

    /* Build UeContext with security context for handover */
    memset(&UeContext, 0, sizeof(UeContext));
    UeContext.supi = amf_ue->supi;

    if (amf_ue->pei)
        UeContext.pei = amf_ue->pei;

    /* SeafData: KAMF and ngKSI */
    memset(&SeafData, 0, sizeof(SeafData));
    memset(&Ng_ksi, 0, sizeof(Ng_ksi));
    memset(&Key_amf, 0, sizeof(Key_amf));
    Ng_ksi.tsc = (amf_ue->nas.ue.tsc == 0) ?
            OpenAPI_sc_type_NATIVE : OpenAPI_sc_type_MAPPED;
    Ng_ksi.ksi = (int)amf_ue->nas.ue.ksi;
    SeafData.ng_ksi = &Ng_ksi;
    Key_amf.key_type = (OpenAPI_key_amf_type_e)OpenAPI_key_amf_type_KAMF;
    ogs_hex_to_ascii(amf_ue->kamf, sizeof(amf_ue->kamf),
            hxkamf_string, sizeof(hxkamf_string));
    Key_amf.key_val = hxkamf_string;
    SeafData.key_amf = &Key_amf;

    /* NH and NCC for handover security context (TS 33.501) */
    ogs_hex_to_ascii(amf_ue->nh, sizeof(amf_ue->nh),
            hxnh_string, sizeof(hxnh_string));
    SeafData.nh = hxnh_string;
    SeafData.is_ncc = true;
    SeafData.ncc = amf_ue->nhcc;

    UeContext.seaf_data = &SeafData;

    /* UE AMBR */
    if (amf_ue->ue_ambr.uplink > 0 || amf_ue->ue_ambr.downlink > 0) {
        UeAmbr = ogs_calloc(1, sizeof(*UeAmbr));
        ogs_assert(UeAmbr);
        if (amf_ue->ue_ambr.uplink > 0)
            UeAmbr->uplink = ogs_sbi_bitrate_to_string(
                    amf_ue->ue_ambr.uplink, OGS_SBI_BITRATE_KBPS);
        if (amf_ue->ue_ambr.downlink > 0)
            UeAmbr->downlink = ogs_sbi_bitrate_to_string(
                    amf_ue->ue_ambr.downlink, OGS_SBI_BITRATE_KBPS);
        UeContext.sub_ue_ambr = UeAmbr;
    }

    /* 5GMM Capability */
    encoded_gmm_capability =
            amf_namf_comm_base64_encode_5gmm_capability(amf_ue);
    UeContext._5g_mm_capability = encoded_gmm_capability;

    /* MmContextList: NAS security mode, UE security capability, allowed NSSAI */
    MmContextList = amf_namf_comm_encode_ue_mm_context_list(amf_ue);
    UeContext.mm_context_list = MmContextList;

    /* Build N2InfoContent for SourceToTarget container */
    memset(&sourceToTargetData, 0, sizeof(sourceToTargetData));
    sourceToTargetData.ngap_ie_type = OpenAPI_ngap_ie_type_SRC_TO_TAR_CONTAINER;
    memset(&ngapData, 0, sizeof(ngapData));
    ngapData.content_id = (char *)"ngap-src-to-tar";
    sourceToTargetData.ngap_data = &ngapData;

    /* Build NGAP Cause */
    memset(&NgapCause, 0, sizeof(NgapCause));
    NgapCause.group = amf_ue->handover.group;
    NgapCause.value = amf_ue->handover.cause;

    /* Build Serving Network (source AMF's PLMN) */
    memset(&ServingNetwork, 0, sizeof(ServingNetwork));
    ogs_assert(ogs_local_conf()->num_of_serving_plmn_id);
    serving_plmn_id = ogs_sbi_build_plmn_id(
            &ogs_local_conf()->serving_plmn_id[0]);
    ogs_assert(serving_plmn_id);
    ServingNetwork.mcc = serving_plmn_id->mcc;
    ServingNetwork.mnc = serving_plmn_id->mnc;

    /* Build n2_notify_uri (callback URI for source AMF) */
    server = ogs_sbi_server_first();
    ogs_assert(server);

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAMF_COMM;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] =
            (char *)OGS_SBI_RESOURCE_NAME_UE_CONTEXTS;
    header.resource.component[1] = amf_ue->supi;
    header.resource.component[2] =
            (char *)OGS_SBI_RESOURCE_NAME_N2_INFO_NOTIFY;

    /* Build UeContextCreateData */
    memset(&UeContextCreateData, 0, sizeof(UeContextCreateData));
    UeContextCreateData.ue_context = &UeContext;
    UeContextCreateData.target_id = targetId;
    UeContextCreateData.source_to_target_data = &sourceToTargetData;
    UeContextCreateData.pdu_session_list = OpenAPI_list_create();
    UeContextCreateData.n2_notify_uri = ogs_sbi_server_uri(server, &header);
    UeContextCreateData.ngap_cause = &NgapCause;
    UeContextCreateData.serving_network = &ServingNetwork;

    message.UeContextCreateData = &UeContextCreateData;

    /* Add SourceToTarget container as binary multipart part */
    container_pkbuf = ogs_pkbuf_alloc(NULL,
            amf_ue->handover.container.size);
    ogs_assert(container_pkbuf);
    ogs_pkbuf_put_data(container_pkbuf,
            amf_ue->handover.container.buf,
            amf_ue->handover.container.size);

    message.part[message.num_of_part].pkbuf = container_pkbuf;
    message.part[message.num_of_part].content_id =
            (char *)"ngap-src-to-tar";
    message.part[message.num_of_part].content_type =
            (char *)OGS_SBI_CONTENT_NGAP_TYPE;
    message.num_of_part++;

    /*
     * Populate pdu_session_list with HR sessions that have N2 SM info
     * from H-SMF (collected via UpdateSMContext in Phase 1A).
     * Each session's handover_request transfer is added as a multipart
     * binary part referenced by content-id "n2-sm-psi-{psi}".
     */
    {
        amf_sess_t *sess = NULL;

        ogs_list_for_each(&amf_ue->sess_list, sess) {
            if (!sess->lbo_roaming_allowed &&
                    SESSION_CONTEXT_IN_SMF(sess) &&
                    sess->transfer.handover_request) {
                OpenAPI_pdu_session_context_t *PduSessionContext = NULL;
                OpenAPI_snssai_t *sNSSAI = NULL;
                ogs_pkbuf_t *n2smbuf = NULL;
                char content_id[32];

                if (message.num_of_part >= OGS_SBI_MAX_NUM_OF_PART) {
                    ogs_warn("Too many multipart parts, "
                            "skipping PSI[%d]", sess->psi);
                    break;
                }

                PduSessionContext =
                        ogs_calloc(1, sizeof(*PduSessionContext));
                ogs_assert(PduSessionContext);

                sNSSAI = ogs_calloc(1, sizeof(*sNSSAI));
                ogs_assert(sNSSAI);

                PduSessionContext->pdu_session_id = sess->psi;
                if (sess->sm_context_resource_uri)
                    PduSessionContext->sm_context_ref =
                        ogs_strdup(sess->sm_context_resource_uri);
                sNSSAI->sst = sess->s_nssai.sst;
                sNSSAI->sd =
                        ogs_s_nssai_sd_to_string(sess->s_nssai.sd);
                PduSessionContext->s_nssai = sNSSAI;
                if (sess->dnn)
                    PduSessionContext->dnn = ogs_strdup(sess->dnn);
                PduSessionContext->access_type =
                    (OpenAPI_access_type_e)amf_ue->nas.access_type;

                OpenAPI_list_add(
                        UeContextCreateData.pdu_session_list,
                        PduSessionContext);

                /* Add N2 SM handover_request as multipart binary part */
                ogs_snprintf(content_id, sizeof(content_id),
                        "n2-sm-psi-%d", sess->psi);

                n2smbuf = ogs_pkbuf_alloc(NULL,
                        sess->transfer.handover_request->len);
                ogs_assert(n2smbuf);
                ogs_pkbuf_put_data(n2smbuf,
                        sess->transfer.handover_request->data,
                        sess->transfer.handover_request->len);

                message.part[message.num_of_part].pkbuf = n2smbuf;
                message.part[message.num_of_part].content_id =
                        ogs_strdup(content_id);
                message.part[message.num_of_part].content_type =
                        (char *)OGS_SBI_CONTENT_NGAP_TYPE;
                message.num_of_part++;

                ogs_info("[%s:%d] Added HR session to CreateUEContext",
                        amf_ue->supi, sess->psi);
            }
        }
    }

    request = ogs_sbi_build_request(&message);
    ogs_expect(request);

    /* Cleanup */
    ogs_pkbuf_free(container_pkbuf);

    /* Free additional multipart parts (N2 SM for HR sessions) */
    {
        int pi;
        for (pi = 1; pi < message.num_of_part; pi++) {
            if (message.part[pi].pkbuf)
                ogs_pkbuf_free(message.part[pi].pkbuf);
            if (message.part[pi].content_id)
                ogs_free(message.part[pi].content_id);
        }
    }

    if (UeContextCreateData.n2_notify_uri)
        ogs_free(UeContextCreateData.n2_notify_uri);
    if (UeContextCreateData.pdu_session_list) {
        OpenAPI_lnode_t *node = NULL;
        OpenAPI_list_for_each(UeContextCreateData.pdu_session_list, node) {
            OpenAPI_pdu_session_context_free(
                    (OpenAPI_pdu_session_context_t *)node->data);
        }
        OpenAPI_list_free(UeContextCreateData.pdu_session_list);
    }
    amf_nsmf_pdusession_free_target_id(targetId);
    if (serving_plmn_id)
        OpenAPI_plmn_id_free(serving_plmn_id);
    if (encoded_gmm_capability)
        ogs_free(encoded_gmm_capability);
    if (UeAmbr)
        OpenAPI_ambr_free(UeAmbr);
    if (MmContextList)
        amf_namf_comm_free_mm_context_list(MmContextList);
    ogs_free(ue_context_id);

    return request;
}

ogs_sbi_request_t *amf_namf_comm_build_registration_status_update(
        amf_ue_t *amf_ue, void *data)
{
    ogs_sbi_message_t message;
    ogs_sbi_request_t *request = NULL;

    OpenAPI_ue_reg_status_update_req_data_t UeRegStatusUpdateReqData;
    char *ue_context_id = NULL;

    ogs_assert(amf_ue);
    ogs_assert(data);

    ue_context_id = ogs_guti_to_string(&amf_ue->old_guti);
    ogs_assert(ue_context_id);

    memset(&message, 0, sizeof(message));
    message.h.method = (char *)OGS_SBI_HTTP_METHOD_POST;
    message.h.service.name = (char *)OGS_SBI_SERVICE_NAME_NAMF_COMM;
    message.h.api.version = (char *)OGS_SBI_API_V1;
    message.h.resource.component[0] =
            (char *)OGS_SBI_RESOURCE_NAME_UE_CONTEXTS;
    message.h.resource.component[1] = ue_context_id;
    message.h.resource.component[2] =
            (char *)OGS_SBI_RESOURCE_NAME_TRANSFER_UPDATE;
    message.UeRegStatusUpdateReqData = &UeRegStatusUpdateReqData;

    memset(&UeRegStatusUpdateReqData, 0, sizeof(UeRegStatusUpdateReqData));

    UeRegStatusUpdateReqData.transfer_status = OGS_POINTER_TO_UINT(data);
    /*
     * TS 29.518
     * 5.2.2.2.2 Registration Status Update
     * If any network slice(s) become no longer available and there are PDU
     * Session(s) associated with them, the target AMF shall include these
     * PDU session(s) in the toReleaseSessionList attribute in the payload.
     */
    if (UeRegStatusUpdateReqData.transfer_status ==
                OpenAPI_ue_context_transfer_status_TRANSFERRED) {
        ogs_assert(amf_ue->to_release_session_list); /* For safety */
        if (amf_ue->to_release_session_list->count) {
            UeRegStatusUpdateReqData.to_release_session_list =
                    amf_ue->to_release_session_list;
        }
    }

    request = ogs_sbi_build_request(&message);
    ogs_expect(request);

    if (ue_context_id)
        ogs_free(ue_context_id);

    return request;
}

ogs_sbi_request_t *amf_namf_comm_build_n2_info_notify(amf_ue_t *amf_ue)
{
    ogs_sbi_request_t *request = NULL;
    cJSON *item = NULL;

    OpenAPI_n2_information_notification_t N2InformationNotification;
    OpenAPI_guami_t *Guami = NULL;

    ogs_assert(amf_ue);
    ogs_assert(amf_ue->n2_notify_uri);
    ogs_assert(amf_ue->guami);

    memset(&N2InformationNotification, 0, sizeof(N2InformationNotification));

    N2InformationNotification.n2_notify_subscription_id =
            amf_ue->supi ? amf_ue->supi : (char *)"unknown";
    N2InformationNotification.notify_reason =
            OpenAPI_n2_info_notify_reason_HANDOVER_COMPLETED;

    Guami = ogs_sbi_build_guami(amf_ue->guami);
    if (!Guami) {
        ogs_error("ogs_sbi_build_guami() failed");
        return NULL;
    }
    N2InformationNotification.guami = Guami;

    request = ogs_sbi_request_new();
    if (!request) {
        ogs_error("ogs_sbi_request_new() failed");
        ogs_sbi_free_guami(Guami);
        return NULL;
    }

    request->h.method = ogs_strdup(OGS_SBI_HTTP_METHOD_POST);
    request->h.uri = ogs_strdup(amf_ue->n2_notify_uri);

    item = OpenAPI_n2_information_notification_convertToJSON(
            &N2InformationNotification);
    ogs_sbi_free_guami(Guami);

    if (!item) {
        ogs_error("OpenAPI_n2_information_notification_convertToJSON() failed");
        ogs_sbi_request_free(request);
        return NULL;
    }

    request->http.content = cJSON_PrintUnformatted(item);
    cJSON_Delete(item);

    if (!request->http.content) {
        ogs_error("cJSON_PrintUnformatted() failed");
        ogs_sbi_request_free(request);
        return NULL;
    }
    request->http.content_length = strlen(request->http.content);

    ogs_sbi_header_set(request->http.headers,
            OGS_SBI_CONTENT_TYPE, OGS_SBI_CONTENT_JSON_TYPE);

    /* User-Agent is needed for SCP routing (requester-nf-type) */
    ogs_sbi_header_set(request->http.headers,
            OGS_SBI_USER_AGENT, (char *)"AMF");

    return request;
}
