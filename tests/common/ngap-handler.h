/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
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

#ifndef TEST_NGAP_HANDLE_H
#define TEST_NGAP_HANDLE_H

#ifdef __cplusplus
extern "C" {
#endif

void testngap_handle_ng_setup_response(
        test_ue_t *test_ue, ogs_ngap_message_t *message);

void testngap_handle_downlink_nas_transport(
        test_ue_t *test_ue, ogs_ngap_message_t *message);
void testngap_handle_initial_context_setup_request(
        test_ue_t *test_ue, ogs_ngap_message_t *message);
void testngap_handle_ue_release_context_command(
        test_ue_t *test_ue, ogs_ngap_message_t *message);

void testngap_handle_pdu_session_resource_setup_request(
        test_ue_t *test_ue, ogs_ngap_message_t *message);
void testngap_handle_pdu_session_resource_modify_request(
        test_ue_t *test_ue, ogs_ngap_message_t *message);
void testngap_handle_pdu_session_resource_release_command(
        test_ue_t *test_ue, ogs_ngap_message_t *message);

void testngap_handle_handover_request(
        test_ue_t *test_ue, ogs_ngap_message_t *message);
void testngap_handle_handover_command(
        test_ue_t *test_ue, ogs_ngap_message_t *message);
void testngap_handle_handover_preparation_failure(
        test_ue_t *test_ue, ogs_ngap_message_t *message);

/* Helper structure for verifying handover failure details */
typedef struct test_handover_failure_s {
    bool received;
    NGAP_Cause_PR cause_group;
    long cause_value;
} test_handover_failure_t;

/* Helper functions for inter-PLMN N2 handover testing */
bool testngap_is_handover_preparation_failure(ogs_ngap_message_t *message);
void testngap_extract_handover_failure_cause(
        ogs_ngap_message_t *message,
        test_handover_failure_t *failure);
bool testngap_is_n14_related_cause(
        NGAP_Cause_PR cause_group,
        long cause_value);

void testngap_handle_handover_cancel_ack(
        test_ue_t *test_ue, ogs_ngap_message_t *message);
void testngap_handle_downlink_ran_status_transfer(
        test_ue_t *test_ue, ogs_ngap_message_t *message);

#ifdef __cplusplus
}
#endif

#endif /* TEST_NGAP_HANDLE_H */
