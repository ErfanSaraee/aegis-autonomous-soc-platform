"""Canonical MITRE ATT&CK Enterprise Threat Intelligence corpus for Hybrid RAG indexing."""

from dataclasses import dataclass

from app.models.soc_models import MITRETactic


@dataclass(frozen=True)
class MITRETechniqueDocument:
    """Structured Cyber Threat Intelligence (CTI) document representing a MITRE ATT&CK technique."""

    technique_id: str
    technique_name: str
    tactic: MITRETactic
    keywords: list[str]
    description: str
    recommended_countermeasure: str


MITRE_ATTACK_CORPUS: list[MITRETechniqueDocument] = [
    MITRETechniqueDocument(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        tactic=MITRETactic.EXECUTION,
        keywords=[
            "powershell",
            "encodedcommand",
            "-enc",
            "invoke-expression",
            "iex",
            "downloadstring",
            "base64",
            "hidden",
            "bypass",
        ],
        description=(
            "Adversaries abuse PowerShell commands and base64-encoded scripts (-EncodedCommand / IEX) "
            "to execute fileless payloads in memory and bypass execution policies."
        ),
        recommended_countermeasure=(
            "Enforce PowerShell Constrained Language Mode, enable Script Block Logging (Event ID 4104), "
            "and isolate the host via EDR."
        ),
    ),
    MITRETechniqueDocument(
        technique_id="T1003.001",
        technique_name="OS Credential Dumping: LSASS Memory",
        tactic=MITRETactic.CREDENTIAL_ACCESS,
        keywords=[
            "mimikatz",
            "sekurlsa",
            "lsass",
            "procdump",
            "ntds.dit",
            "dcsync",
            "credential",
            "hash",
            "/etc/shadow",
            "kerberoast",
        ],
        description=(
            "Adversaries attempt to dump credential material from the Local Security Authority "
            "Subsystem Service (LSASS) process memory using tools like Mimikatz or ProcDump."
        ),
        recommended_countermeasure=(
            "Enable Windows Defender Credential Guard (LSA Protection / RunAsPPL), revoke active "
            "Kerberos TGT tickets, and force immediate password rotation for privileged accounts."
        ),
    ),
    MITRETechniqueDocument(
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares & PsExec",
        tactic=MITRETactic.LATERAL_MOVEMENT,
        keywords=[
            "psexec",
            "smb",
            "admin$",
            "c$",
            "ipc$",
            "wmic",
            "lateral",
            "pass-the-hash",
            "winrm",
            "rpc",
        ],
        description=(
            "Adversaries leverage valid accounts or stolen NTLM hashes with SMB administrative shares "
            "(ADMIN$, C$) and PsExec/WMI to move laterally across enterprise servers."
        ),
        recommended_countermeasure=(
            "Segment internal SMB traffic (TCP 445) via host firewall rules, disable administrative "
            "shares on non-domain controllers, and quarantine affected source/target endpoints."
        ),
    ),
    MITRETechniqueDocument(
        technique_id="T1490",
        technique_name="Inhibit System Recovery & Shadow Copy Deletion (Ransomware Precursor)",
        tactic=MITRETactic.EXECUTION,
        keywords=[
            "vssadmin",
            "shadowcopy",
            "delete",
            "shadows",
            "wbadmin",
            "bcdedit",
            "recoveryenabled",
            "ransomware",
            "encrypt",
        ],
        description=(
            "Adversaries delete Volume Shadow Copies using vssadmin, wmic, or wbadmin to prevent "
            "enterprise recovery immediately prior to ransomware payload encryption."
        ),
        recommended_countermeasure=(
            "Immediately isolate host at the EDR network layer, terminate offending child processes, "
            "and verify immutable offline backup snapshots."
        ),
    ),
    MITRETechniqueDocument(
        technique_id="T1071.001",
        technique_name="Application Layer Protocol: Web Protocols (C2 Beaconing)",
        tactic=MITRETactic.COMMAND_AND_CONTROL,
        keywords=[
            "cobaltstrike",
            "beacon",
            "meterpreter",
            "c2",
            "callback",
            "webhook",
            "user-agent",
            "reverse",
            "tunnel",
        ],
        description=(
            "Adversaries communicate with external Command and Control (C2) infrastructure over "
            "HTTP/HTTPS beaconing intervals using Cobalt Strike or custom reverse shells."
        ),
        recommended_countermeasure=(
            "Block the malicious C2 egress IP/domain at the perimeter firewall, terminate beacon "
            "processes, and inspect proxy logs for other internal hosts communicating with the C2 IP."
        ),
    ),
    MITRETechniqueDocument(
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel & Sensitive Credential Leakage",
        tactic=MITRETactic.EXFILTRATION,
        keywords=[
            "exfiltrate",
            "upload",
            "archive",
            "curl",
            "sk-",
            "akia",
            "api_key",
            "dump",
            "outbound",
            "transfer",
        ],
        description=(
            "Adversaries steal sensitive enterprise databases, API keys, or customer PII by "
            "compressing and transmitting large outbound byte streams to external servers."
        ),
        recommended_countermeasure=(
            "Drop active outbound sessions to the destination IP, revoke exposed API keys/tokens "
            "immediately, and trigger DLP forensic auditing."
        ),
    ),
    MITRETechniqueDocument(
        technique_id="T1110.003",
        technique_name="Brute Force: Password Spraying & Credential Stuffing",
        tactic=MITRETactic.INITIAL_ACCESS,
        keywords=[
            "brute",
            "spray",
            "failed",
            "login",
            "authentication",
            "ssh",
            "rdp",
            "4625",
            "unauthorized",
        ],
        description=(
            "Adversaries attempt high-volume authentication requests across SSH, RDP, or SSO "
            "endpoints to compromise accounts with weak credentials."
        ),
        recommended_countermeasure=(
            "Rate-limit and block the offending source IP at the WAF/Firewall, enforce MFA, "
            "and lock targeted accounts temporarily."
        ),
    ),
]
