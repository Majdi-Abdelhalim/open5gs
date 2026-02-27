#!/usr/bin/env python3
"""
ho-pcap-to-csv.py — Extract and classify inter-PLMN N2 handover messages from pcap

Generates a CSV with per-message details matching the pcap verification guide
steps in docs/interplmn-n2-handover-pcap-verification.md.

Usage:
    python3 scripts/ho-pcap-to-csv.py <pcap_file> [output_csv]

Output columns:
    frame_number, timestamp_sec, src_ip, src_entity, dst_ip, dst_entity,
    port, protocol, message_type, description, phase, step_ref, spec_reference
"""

import csv
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# IP ↔ entity mapping
# ---------------------------------------------------------------------------
ENTITY_MAP = {
    "127.0.1.5":   "H-AMF",
    "127.0.2.5":   "V-AMF",
    "127.0.0.2":   "SRC-gNB",
    "127.0.0.3":   "TGT-gNB",
    "127.0.1.4":   "H-SMF",
    "127.0.2.4":   "V-SMF",
    "127.0.1.7":   "H-UPF",
    "127.0.2.7":   "V-UPF",
    "127.0.1.200": "SCP1",
    "127.0.2.200": "SCP2",
    "127.0.1.250": "SEPP1",
    "127.0.2.250": "SEPP2",
    "127.0.1.252": "SEPP1-N32",
    "127.0.2.252": "SEPP2-N32",
    "127.0.1.10":  "NRF1",
    "127.0.2.10":  "NRF2",
    "127.0.1.11":  "AUSF",
    "127.0.1.12":  "UDM",
    "127.0.1.15":  "BSF",
    "127.0.1.20":  "UDR",
    "127.0.0.1":   "NF",
}

def entity(ip: str) -> str:
    return ENTITY_MAP.get(ip, ip)


def is_visited_plmn(ip: str) -> bool:
    """True when the IP is in the Visiting PLMN subnet (127.0.2.x)."""
    return ip.startswith("127.0.2.")


def is_home_plmn(ip: str) -> bool:
    """True when the IP is in the Home PLMN subnet (127.0.1.x)."""
    return ip.startswith("127.0.1.")


# ---------------------------------------------------------------------------
# NGAP procedure code → initiating / successful names
# ---------------------------------------------------------------------------
NGAP_INITIATING = {
    "4":  "DownlinkNASTransport",
    "7":  "DownlinkRANStatusTransfer",
    "11": "HandoverNotify",
    "12": "HandoverRequired",
    "13": "HandoverRequest",
    "14": "InitialContextSetupRequest",
    "15": "InitialUEMessage",
    "21": "NGSetupRequest",
    "29": "PDUSessionResourceSetupRequest",
    "41": "UEContextReleaseCommand",
    "42": "UEContextReleaseRequest",
    "44": "UERadioCapabilityInfoIndication",
    "46": "UplinkNASTransport",
    "49": "UplinkRANStatusTransfer",
}
NGAP_SUCCESSFUL = {
    "12": "HandoverCommand",
    "13": "HandoverRequestAcknowledge",
    "14": "InitialContextSetupResponse",
    "21": "NGSetupResponse",
    "29": "PDUSessionResourceSetupResponse",
    "41": "UEContextReleaseComplete",
}

# ---------------------------------------------------------------------------
# Classification rules → (description, phase, step_ref, spec_reference)
# ---------------------------------------------------------------------------
# NGAP keyed by (name,) or (name, src_entity, dst_entity)
NGAP_CLASS = {
    "NGSetupRequest": (
        "gNB registers with AMF",
        "Phase 0 — Setup",
        "Pre-handover (gNB/AMF))",
        "TS 38.413 §9.3.3.1",
    ),
    "NGSetupResponse": (
        "AMF confirms gNB registration",
        "Phase 0 — Setup",
        "Pre-handover (gNB/AMF)",
        "TS 38.413 §9.3.3.1",
    ),
    "InitialUEMessage": (
        "UE Registration Request from source gNB",
        "Phase 1 — Registration",
        "Step 1a (UE → SRC-gNB → H-AMF)",
        "TS 38.413 §9.3.5.1 / TS 23.502 §4.2.2.2",
    ),
    "DownlinkNASTransport": (
        "NAS downlink message (Identity/Auth/Security)",
        "Phase 1 — Registration",
        "Step 1 DL NAS",
        "TS 38.413 §9.3.5.2",
    ),
    "UplinkNASTransport": (
        "NAS uplink message (Identity/Auth/Security response)",
        "Phase 1 — Registration",
        "Step 1 UL NAS",
        "TS 38.413 §9.3.5.3",
    ),
    "InitialContextSetupRequest": (
        "AMF establishes UE context at source gNB",
        "Phase 1 — Registration",
        "Step 1 InitialContextSetup",
        "TS 38.413 §9.3.1.1 / TS 23.502 §4.2.2.2",
    ),
    "InitialContextSetupResponse": (
        "Source gNB confirms UE context established",
        "Phase 1 — Registration",
        "Step 1 InitialContextSetup",
        "TS 38.413 §9.3.1.1",
    ),
    "UERadioCapabilityInfoIndication": (
        "Source gNB reports UE radio capability",
        "Phase 1 — Registration",
        "Step 1 (optional)",
        "TS 38.413 §9.3.1.13",
    ),
    "PDUSessionResourceSetupRequest": (
        "AMF sends PDU session resource setup to source gNB",
        "Phase 1 — Session Setup",
        "Step 1h (H-AMF → SRC-gNB) / TS 23.502 §4.3.2",
        "TS 38.413 §9.3.2.1",
    ),
    "PDUSessionResourceSetupResponse": (
        "Source gNB confirms PDU session resource setup",
        "Phase 1 — Session Setup",
        "Step 1i (SRC-gNB → H-AMF) / TS 23.502 §4.3.2",
        "TS 38.413 §9.3.2.1",
    ),
    "HandoverRequired": (
        "Source gNB initiates handover; H-AMF begins HO preparation",
        "Phase 2 — HO Preparation",
        "Step 2a (SRC-gNB → H-AMF)",
        "TS 38.413 §9.3.6.3 / TS 23.502 §4.23.7.3 Step 1",
    ),
    "HandoverRequest": (
        "V-AMF requests target gNB to allocate HO resources",
        "Phase 2 — HO Preparation",
        "Step 2e (V-AMF → TGT-gNB)",
        "TS 38.413 §9.3.6.3 / TS 23.502 §4.23.7.3 Step 10",
    ),
    "HandoverRequestAcknowledge": (
        "Target gNB confirms HO resource allocation; includes DL forwarding tunnel",
        "Phase 2 — HO Preparation",
        "Step 2e (TGT-gNB → V-AMF)",
        "TS 38.413 §9.3.6.3 / TS 23.502 §4.23.7.3 Step 11",
    ),
    "HandoverCommand": (
        "H-AMF commands source gNB to hand over UE",
        "Phase 2 — HO Preparation",
        "Step 2g (H-AMF → SRC-gNB)",
        "TS 38.413 §9.3.6.3 / TS 23.502 §4.23.7.3 Step 13",
    ),
    "UplinkRANStatusTransfer": (
        "Source gNB forwards PDCP SN status to H-AMF for delivery to target",
        "Phase 2 — HO Execution",
        "HR RANStatus Step 1 (SRC-gNB → H-AMF)",
        "TS 38.413 §9.3.6.5 / TS 23.502 §4.23.7.3 Step 14",
    ),
    "DownlinkRANStatusTransfer": (
        "V-AMF delivers PDCP SN status from source to target gNB",
        "Phase 2 — HO Execution",
        "HR RANStatus Step 3 (V-AMF → TGT-gNB)",
        "TS 38.413 §9.3.6.5 / TS 23.502 §4.23.7.3 Step 16",
    ),
    "HandoverNotify": (
        "Target gNB signals UE has arrived; HO complete at RAN",
        "Phase 3 — HO Completion",
        "Step 3a (TGT-gNB → V-AMF)",
        "TS 38.413 §9.3.3.3 / TS 23.502 §4.23.7.3 Step 17",
    ),
    "UEContextReleaseCommand": (
        "AMF releases UE context at gNB",
        "Phase 4 — Cleanup",
        "Step 4 UECtxRelease",
        "TS 38.413 §9.3.6.4 / TS 23.502 §4.23.7.3 Step 23",
    ),
    "UEContextReleaseComplete": (
        "gNB confirms UE context released",
        "Phase 4 — Cleanup",
        "Step 4 UECtxRelease",
        "TS 38.413 §9.3.6.4 / TS 23.502 §4.23.7.3 Step 23",
    ),
    "UEContextReleaseRequest": (
        "Target gNB requests V-AMF to release UE context",
        "Phase 4 — Cleanup",
        "Step 4 (TGT-gNB → V-AMF)",
        "TS 38.413 §9.3.6.2 / TS 23.502 §4.23.7.3 Step 22",
    ),
}

# ---------------------------------------------------------------------------
# SBI path classification
# (path_pattern, method, dst_plmn) → (message_type, description, phase, step_ref, spec_ref)
# dst_plmn: "home" | "visited" | None (any)
# Checked in order; first match wins.
# ---------------------------------------------------------------------------
SBI_RULES = [
    # ── Registration / Auth ─────────────────────────────────────────────────
    (r"^/nausf-auth",    "POST", None,    "Nausf_UEAuthentication Create",
     "UE authentication initiation",
     "Phase 1 — Registration", "Auth SBI",
     "TS 29.509 §5.2.2 / TS 23.502 §4.2.2.2"),

    (r"^/nudm-ueau",     None,   None,    "Nudm_UEAuthentication Get",
     "UDM provides authentication vector",
     "Phase 1 — Registration", "Auth SBI",
     "TS 29.503 §5.2.2 / TS 23.502 §4.2.2.2"),

    (r"^/nudm-uecm",     None,   None,    "Nudm_UECM Registration",
     "AMF registers UE context at UDM",
     "Phase 1 — Registration", "Registration SBI",
     "TS 29.503 §5.2.3"),

    (r"^/nudm-sdm/v\d+/[^/]+/ue-context-in-smf-data", "GET", None,
     "Nudm_SDM_Get UE Context in SMF Data",
     "AMF retrieves existing SMF PDU session list from UDM",
     "Phase 1 — Registration", "Registration SBI",
     "TS 29.503 §5.2.4"),

    (r"^/nudm-sdm",      "GET",  None,    "Nudm_SDM Get",
     "AMF/SMF retrieves subscription data from UDM",
     "Phase 1 — Registration", "Registration SBI",
     "TS 29.503 §5.2.4"),

    (r"^/nudr-dr/v1/subscription-data/.*/authentication-data", None, None,
     "Nudr_DM Authentication Data",
     "UDR subscription authentication data access",
     "Phase 1 — Registration", "Registration SBI",
     "TS 29.504 §5.2.2"),

    (r"^/nudr-dr/v1/subscription-data/.*/context-data/amf-3gpp-access", None, None,
     "Nudr_DM AMF Context",
     "UDR stores AMF 3GPP access context",
     "Phase 1 — Registration", "Registration SBI",
     "TS 29.504 §5.2.2"),

    (r"^/nudr-dr/v1/subscription-data/.*/context-data/smf-registrations", None, None,
     "Nudr_DM SMF Registration",
     "UDR stores SMF PDU session registration",
     "Phase 1 — Session Setup", "Session SBI",
     "TS 29.504 §5.2.2"),

    (r"^/nudr-dr/v1/subscription-data/.*/provisioned-data", None, None,
     "Nudr_DM Provisioned Data",
     "UDR provides provisioned subscription data",
     "Phase 1 — Registration", "Registration SBI",
     "TS 29.504 §5.2.2"),

    (r"^/nudr-dr/v1/policy-data", None, None,
     "Nudr_DM Policy Data",
     "UDR provides policy data for PCF",
     "Phase 1 — Registration", "Registration SBI",
     "TS 29.504 §5.2.2"),

    (r"^/nbsf-management", None, None,
     "Nbsf_Management Create",
     "PCF creates BSF binding",
     "Phase 1 — Session Setup", "Session SBI",
     "TS 29.521 §5.2.2"),

    (r"^/nnrf-nfm", None, None,
     "Nnrf_NFManagement Update",
     "NF heartbeat / NF profile registration",
     "Phase 0 — Setup", "NF Registration (heartbeat)",
     "TS 29.510 §5.2.3"),

    # ── Session Setup ────────────────────────────────────────────────────────
    (r"^/nsmf-pdusession/v1/sm-contexts$", "POST", "home",
     "Nsmf_PDUSession_CreateSMContext (H-SMF)",
     "H-AMF creates PDU session at H-SMF (initial session)",
     "Phase 1 — Session Setup", "Step 1d-e (H-AMF → H-SMF via SCP1)",
     "TS 29.502 §5.2.2 / TS 23.502 §4.3.2"),

    (r"^/namf-comm/v1/ue-contexts/[^/]+/n1-n2-messages$", "POST", None,
     "Namf_Communication_N1N2MessageTransfer",
     "H-SMF delivers NAS PDU and N2 SM info to H-AMF",
     "Phase 1 — Session Setup", "Step 1f-g (H-SMF → H-AMF via SCP1)",
     "TS 29.518 §5.2.5.5 / TS 23.502 §4.3.2"),

    # ── HO Preparation: H-AMF → H-SMF modify (following HandoverRequired) ───
    (r"^/nsmf-pdusession/v1/sm-contexts/[^/]+/modify$", "POST", "home",
     "Nsmf_PDUSession_UpdateSMContext (H-SMF)",
     "H-AMF/H-UPF UpdateSMContext to H-SMF (DL FAR activation or HO prep)",
     "Phase 1/2 — Session Setup / HO Preparation", "Step 1i DL or Step 2b (H-AMF → H-SMF via SCP1)",
     "TS 29.502 §5.2.5 / TS 23.502 §4.3.2 / §4.23.7.3 Step 2-3"),

    # ── NRF Discovery for T-AMF (through SEPP) ───────────────────────────────
    (r"^/nnrf-disc/v1/nf-instances", "GET", None,
     "Nnrf_NFDiscovery Request (T-AMF lookup)",
     "NRF discovery for target AMF through SEPP chain",
     "Phase 2 — HO Preparation", "Step 2c (SCP1 → NRF route via SEPP)",
     "TS 29.510 §5.2.10 / TS 23.502 §4.23.7.3 Step 4-5"),

    # ── CreateUEContext (5-hop SEPP chain) ───────────────────────────────────
    (r"^/namf-comm/v1/ue-contexts/[^/]+$", "POST", None,
     "Namf_Communication_CreateUEContext",
     "H-AMF sends CreateUEContext to V-AMF through SEPP chain (5 hops)",
     "Phase 2 — HO Preparation", "Step 2d (H-AMF → V-AMF, 5 hops via SEPP)",
     "TS 29.518 §5.2.5.4 / TS 23.502 §4.23.7.3 Step 6"),

    # ── V-SMF CreateSMContext PREPARING (via Visited PLMN SCP/SEPP/NF) ──────
    (r"^/nsmf-pdusession/v1/sm-contexts$", "POST", "visited",
     "Nsmf_PDUSession_CreateSMContext hoState=PREPARING (V-SMF)",
     "V-AMF inserts V-SMF: CreateSMContext with hoState=PREPARING",
     "Phase 2 — HO Preparation (HR V-SMF Insertion)", "HR Step 3-4 (V-AMF → V-SMF via SCP2)",
     "TS 29.502 §5.2.2 / TS 23.502 §4.23.7.3 Step 7"),

    # ── V-SMF → H-SMF Create (through SEPP) ─────────────────────────────────
    (r"^/nsmf-pdusession/v1/pdu-sessions$", "POST", None,
     "Nsmf_PDUSession_Create HO (V-SMF → H-SMF)",
     "V-SMF creates PDU sessions at H-SMF with ho_preparation_indication",
     "Phase 2 — HO Preparation (HR V-SMF Insertion)", "HR Step 5-6 (V-SMF → H-SMF via SEPP chain)",
     "TS 29.502 §5.2.2 / TS 23.502 §4.23.7.3 Step 9"),

    # ── V-SMF UpdateSMContext PREPARED/COMPLETED (via Visited PLMN route) ───
    (r"^/nsmf-pdusession/v1/sm-contexts/[^/]+/modify$", "POST", "visited",
     "Nsmf_PDUSession_UpdateSMContext (V-SMF)",
     "V-AMF sends UpdateSMContext to V-SMF (PREPARED/COMPLETED/cleanup)",
     "Phase 2/3 — HO Preparation/Completion", "HR: V-AMF → V-SMF via SCP2",
     "TS 29.502 §5.2.5 / TS 23.502 §4.23.7.3 Step 12/18"),

    # ── N2InfoNotify (any) ────────────────────────────────────────────────────
    (r"^/namf-comm/v1/ue-contexts/[^/]+/n2-info-notify$", "POST", "visited",
     "Namf_Communication_N2InfoNotify (→ V-AMF)",
     "Notify V-AMF (RAN status transfer from H-AMF routed through SEPP)",
     "Phase 2 — HO Execution", "HR RANStatus Step 2 (H-AMF → V-AMF via SEPP)",
     "TS 29.518 §5.2.5.6 / TS 23.502 §4.23.7.3 Step 15"),

    (r"^/namf-comm/v1/ue-contexts/[^/]+/n2-info-notify$", "POST", "home",
     "Namf_Communication_N2InfoNotify (→ H-AMF)",
     "Notify H-AMF of handover completion (V-AMF routed through SEPP)",
     "Phase 3 — HO Completion", "Step 3b (V-AMF → H-AMF via SEPP, 5 hops)",
     "TS 29.518 §5.2.5.6 / TS 23.502 §4.23.7.3 Step 19-21"),

    # ── V-SMF → H-SMF pdu-sessions modify ────────────────────────────────────
    (r"^/nsmf-pdusession/v1/pdu-sessions/[^/]+/modify$", "POST", None,
     "Nsmf_PDUSession_Update (V-SMF → H-SMF)",
     "V-SMF updates H-SMF with new data path info (DL switch / cleanup)",
     "Phase 3/4 — HO Completion/Cleanup", "HR: V-SMF → H-SMF via SEPP chain",
     "TS 29.502 §5.2.3 / TS 23.502 §4.23.7.3"),

    # ── H-SMF PDU session release ─────────────────────────────────────────────
    (r"^/nsmf-pdusession/v1/sm-contexts/[^/]+/release$", "POST", None,
     "Nsmf_PDUSession_Release (H-SMF)",
     "H-AMF releases PDU session at H-SMF (source side cleanup)",
     "Phase 4 — Cleanup", "Step 4 (H-AMF → H-SMF via SCP1)",
     "TS 29.502 §5.2.6 / TS 23.502 §4.23.7.3 Step 20+"),

    # ── Catch-all SBI ─────────────────────────────────────────────────────────
    (r".*", None, None,
     "SBI (Other)",
     "Other SBI message",
     "Phase 0/1 — Setup/Registration", "",
     "TS 29.500"),
]

# ---------------------------------------------------------------------------
# PFCP classification
# ---------------------------------------------------------------------------
PFCP_CLASS = {
    "PFCP Heartbeat Request": (
        "N4 keepalive from SMF to UPF",
        "Phase 0 — Setup", "N4 Heartbeat",
        "TS 29.244 §6.2.5",
    ),
    "PFCP Heartbeat Response": (
        "N4 keepalive response from UPF to SMF",
        "Phase 0 — Setup", "N4 Heartbeat",
        "TS 29.244 §6.2.5",
    ),
    "PFCP Session Establishment Request": (
        "SMF establishes N4 session at UPF (FAR/PDR/QER setup)",
        "Phase 1 — Session Setup", "N4 Session Establishment",
        "TS 29.244 §7.4 / TS 23.502 §4.3.2",
    ),
    "PFCP Session Establishment Response": (
        "UPF confirms N4 session establishment",
        "Phase 1 — Session Setup", "N4 Session Establishment",
        "TS 29.244 §7.4",
    ),
    "PFCP Session Report Request": (
        "UPF reports uplink data arrival to SMF (buffered UL data)",
        "Phase 1 — Session Setup", "N4 Uplink Data Notify",
        "TS 29.244 §7.7 / TS 23.502 §4.3.2",
    ),
    "PFCP Session Report Response": (
        "SMF processes UPF uplink data report",
        "Phase 1 — Session Setup", "N4 Uplink Data Notify",
        "TS 29.244 §7.7",
    ),
    "PFCP Session Modification Request": (
        "SMF modifies N4 session at UPF (DL FAR activation / path switch / cleanup)",
        "Phase 1/2/3 — Session/HO", "N4 Session Modification",
        "TS 29.244 §7.5 / TS 23.502 §4.23.7.3",
    ),
    "PFCP Session Modification Response": (
        "UPF confirms N4 session modification",
        "Phase 1/2/3 — Session/HO", "N4 Session Modification",
        "TS 29.244 §7.5",
    ),
    "PFCP Session Deletion Request": (
        "SMF deletes N4 session at UPF",
        "Phase 4 — Cleanup", "N4 Session Deletion",
        "TS 29.244 §7.6",
    ),
    "PFCP Session Deletion Response": (
        "UPF confirms N4 session deletion",
        "Phase 4 — Cleanup", "N4 Session Deletion",
        "TS 29.244 §7.6",
    ),
}


# ---------------------------------------------------------------------------
# tshark helpers
# ---------------------------------------------------------------------------
def run_tshark(pcap: str, extra_args: list[str]) -> list[str]:
    cmd = ["tshark", "-r", pcap] + extra_args
    result = subprocess.run(cmd, capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line.strip()]


def fields_cmd(pcap: str, display_filter: str, fields: list[str],
               decode_as: list[str] | None = None) -> list[list[str]]:
    args = []
    for d in (decode_as or []):
        args += ["-d", d]
    args += ["-Y", display_filter, "-T", "fields"]
    for f in fields:
        args += ["-e", f]
    args += ["-E", "separator=\x01"]  # use SOH as safe separator
    lines = run_tshark(pcap, args)
    rows = []
    for line in lines:
        cols = line.split("\x01")
        # pad to expected length
        while len(cols) < len(fields):
            cols.append("")
        rows.append(cols)
    return rows


# ---------------------------------------------------------------------------
# Classify SBI messages
# ---------------------------------------------------------------------------
def classify_sbi(path: str, method: str, dst_ip: str) -> tuple[str, str, str, str, str]:
    """Match SBI message against rules. dst_plmn is "home" | "visited" | None."""
    if is_visited_plmn(dst_ip):
        dst_plmn = "visited"
    elif is_home_plmn(dst_ip):
        dst_plmn = "home"
    else:
        dst_plmn = None

    for pattern, req_method, req_plmn, msg_type, desc, phase, step, spec in SBI_RULES:
        if req_method and req_method != method:
            continue
        if req_plmn and req_plmn != dst_plmn:
            continue
        if re.match(pattern, path):
            return msg_type, desc, phase, step, spec
    return "SBI (Unknown)", path, "Unknown", "", "TS 29.500"


# ---------------------------------------------------------------------------
# Classify PFCP messages — refine phase based on src/dst
# ---------------------------------------------------------------------------
def classify_pfcp(info: str, src_ip: str, dst_ip: str) -> tuple[str, str, str, str, str]:
    info_key = info.strip()
    base = PFCP_CLASS.get(info_key)
    if not base:
        return info_key, info_key, "Unknown", "", "TS 29.244"
    msg_type = info_key
    description, phase, step_ref, spec = base

    # refine phase for Modification based on which UPF was involved
    src_ent = entity(src_ip)
    dst_ent = entity(dst_ip)
    if "Modification" in info_key:
        if src_ent in ("H-SMF", "H-UPF") or dst_ent in ("H-UPF", "H-SMF"):
            if dst_ent == "H-UPF" or src_ent == "H-SMF":
                description = ("H-SMF modifies H-UPF N4 session"
                               " (DL path setup or H-UPF update after V-SMF)")
    if "Establishment" in info_key:
        src_ent = entity(src_ip)
        if src_ent == "V-SMF":
            description = "V-SMF establishes N4 session at V-UPF (HR preparation)"
            phase = "Phase 2 — HO Preparation (HR)"
            step_ref = "HR N4 Setup (V-SMF → V-UPF)"
            spec = "TS 29.244 §7.4 / TS 23.502 §4.23.7.3 Step 7"
    return msg_type, description, phase, step_ref, spec


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------
def extract_ngap(pcap: str) -> list[dict]:
    rows = fields_cmd(
        pcap,
        "ngap",
        [
            "frame.number", "frame.time_relative",
            "ip.src", "ip.dst", "sctp.dstport",
            "ngap.procedureCode",
            "ngap.initiatingMessage_element",
            "ngap.successfulOutcome_element",
            "_ws.col.Info",
        ],
    )
    records = []
    for r in rows:
        (fnum, ts, src, dst, port,
         proc_code, is_init, is_succ, info) = r[:9]

        if is_init == "1":
            msg_type = NGAP_INITIATING.get(proc_code, f"NGAP-proc{proc_code}-Init")
        elif is_succ == "1":
            msg_type = NGAP_SUCCESSFUL.get(proc_code, f"NGAP-proc{proc_code}-Succ")
        else:
            # Unsuccessful outcome or unknown — try to parse from Info
            for name in list(NGAP_INITIATING.values()) + list(NGAP_SUCCESSFUL.values()):
                if name in info:
                    msg_type = name
                    break
            else:
                msg_type = f"NGAP-proc{proc_code}"

        cls = NGAP_CLASS.get(msg_type, (
            msg_type, "Phase ?", "?", "TS 38.413",
        ))
        description, phase, step_ref, spec = cls

        records.append({
            "frame_number":  fnum,
            "timestamp_sec": ts,
            "src_ip":        src,
            "src_entity":    entity(src),
            "dst_ip":        dst,
            "dst_entity":    entity(dst),
            "port":          port,
            "protocol":      "NGAP (SCTP)",
            "message_type":  msg_type,
            "description":   description,
            "phase":         phase,
            "step_ref":      step_ref,
            "spec_reference": spec,
        })
    return records


def extract_sbi(pcap: str) -> list[dict]:
    decode_as = ["tcp.port==7777,http2", "tcp.port==80,http2"]
    rows = fields_cmd(
        pcap,
        "http2.headers.path",
        [
            "frame.number", "frame.time_relative",
            "ip.src", "ip.dst", "tcp.dstport",
            "http2.headers.method",
            "http2.headers.path",
            "http2.headers.status",
        ],
        decode_as=decode_as,
    )
    records = []
    for r in rows:
        fnum, ts, src, dst, port, method, path, status = r[:8]
        if not path:
            continue  # skip frames without a :path header (e.g. SETTINGS)

        msg_type, description, phase, step_ref, spec = classify_sbi(
            path, method, dst
        )

        # add HTTP status to description for response frames
        if status:
            description = f"{description} [HTTP {status}]"

        records.append({
            "frame_number":  fnum,
            "timestamp_sec": ts,
            "src_ip":        src,
            "src_entity":    entity(src),
            "dst_ip":        dst,
            "dst_entity":    entity(dst),
            "port":          port,
            "protocol":      f"SBI (HTTP/2)",
            "message_type":  msg_type,
            "description":   description,
            "phase":         phase,
            "step_ref":      step_ref,
            "spec_reference": spec,
        })
    return records


def extract_pfcp(pcap: str) -> list[dict]:
    rows = fields_cmd(
        pcap,
        "pfcp",
        [
            "frame.number", "frame.time_relative",
            "ip.src", "ip.dst", "udp.dstport",
            "_ws.col.Info",
        ],
    )
    records = []
    for r in rows:
        fnum, ts, src, dst, port, info = r[:6]
        msg_type, description, phase, step_ref, spec = classify_pfcp(
            info, src, dst
        )
        records.append({
            "frame_number":  fnum,
            "timestamp_sec": ts,
            "src_ip":        src,
            "src_entity":    entity(src),
            "dst_ip":        dst,
            "dst_entity":    entity(dst),
            "port":          port,
            "protocol":      "PFCP (UDP)",
            "message_type":  msg_type,
            "description":   description,
            "phase":         phase,
            "step_ref":      step_ref,
            "spec_reference": spec,
        })
    return records


def extract_gtp(pcap: str) -> list[dict]:
    """Extract GTP-U/GPRS messages (data plane indicator)."""
    rows = fields_cmd(
        pcap,
        "gtp",
        [
            "frame.number", "frame.time_relative",
            "ip.src", "ip.dst", "udp.dstport",
            "_ws.col.Info",
        ],
    )
    records = []
    for r in rows:
        fnum, ts, src, dst, port, info = r[:6]
        records.append({
            "frame_number":  fnum,
            "timestamp_sec": ts,
            "src_ip":        src,
            "src_entity":    entity(src),
            "dst_ip":        dst,
            "dst_entity":    entity(dst),
            "port":          port,
            "protocol":      "GTP-U (UDP)",
            "message_type":  info.strip() or "GTP-U",
            "description":   "User-plane GTP data / echo (N3 data path)",
            "phase":         "Phase 1+ — Data Path",
            "step_ref":      "N3 GTP-U data",
            "spec_reference": "TS 29.281 / TS 38.415",
        })
    return records


# ---------------------------------------------------------------------------
# Merge and sort by frame number
# ---------------------------------------------------------------------------
def merge_sort(records: list[dict]) -> list[dict]:
    def key(r: dict) -> int:
        try:
            return int(r["frame_number"])
        except (ValueError, KeyError):
            return 0
    return sorted(records, key=key)


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------
FIELDNAMES = [
    "frame_number",
    "timestamp_sec",
    "src_ip",
    "src_entity",
    "dst_ip",
    "dst_entity",
    "port",
    "protocol",
    "message_type",
    "description",
    "phase",
    "step_ref",
    "spec_reference",
]


def write_csv(records: list[dict], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(records)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file> [output_csv]", file=sys.stderr)
        sys.exit(1)

    pcap = sys.argv[1]
    if not Path(pcap).exists():
        print(f"ERROR: File not found: {pcap}", file=sys.stderr)
        sys.exit(1)

    # Default output: current working directory (project root when run from there)
    if len(sys.argv) >= 3:
        output_csv = sys.argv[2]
    else:
        stem = Path(pcap).stem
        output_csv = str(Path.cwd() / f"{stem}_messages.csv")

    print(f"Extracting NGAP messages …", flush=True)
    ngap_records = extract_ngap(pcap)

    print(f"Extracting SBI (HTTP/2) messages …", flush=True)
    sbi_records = extract_sbi(pcap)

    print(f"Extracting PFCP messages …", flush=True)
    pfcp_records = extract_pfcp(pcap)

    print(f"Extracting GTP-U messages …", flush=True)
    gtp_records = extract_gtp(pcap)

    all_records = merge_sort(ngap_records + sbi_records + pfcp_records + gtp_records)

    write_csv(all_records, output_csv)

    # Print summary
    total = len(all_records)
    by_proto = {}
    for r in all_records:
        p = r["protocol"].split(" ")[0]
        by_proto[p] = by_proto.get(p, 0) + 1

    print(f"\nExtracted {total} messages → {output_csv}")
    for proto, count in sorted(by_proto.items(), key=lambda x: -x[1]):
        print(f"  {proto:<12} {count:>4} frames")


if __name__ == "__main__":
    main()
