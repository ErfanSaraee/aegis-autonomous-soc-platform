"""8D SIEM telemetry feature engineering and stratified Pandas/NumPy training generator."""

import hashlib
import math
import re

import numpy as np
import pandas as pd
import torch

FEATURE_COLUMNS: list[str] = [
    "log_length_norm",
    "suspicious_token_density",
    "network_bytes_log_norm",
    "failed_auth_norm",
    "process_entropy_norm",
    "privilege_escalation_score",
    "lateral_movement_c2_score",
    "obfuscation_indicator_score",
]

# Weighted dictionary of high-signal adversarial SOC tokens (1..36 reserved for PyTorch vocab)
SOC_ADVERSARIAL_TOKENS: dict[str, float] = {
    "powershell": 1.25,
    "encodedcommand": 1.65,
    "-enc": 1.60,
    "mimikatz": 1.90,
    "sekurlsa": 1.90,
    "lsass": 1.75,
    "psexec": 1.65,
    "wmic": 1.45,
    "vssadmin": 1.80,
    "shadowcopy": 1.80,
    "ntds.dit": 1.85,
    "certutil": 1.50,
    "cobaltstrike": 1.90,
    "beacon": 1.40,
    "meterpreter": 1.85,
    "reverse": 1.30,
    "/etc/shadow": 1.85,
    "/etc/passwd": 1.65,
    "chmod": 1.20,
    "sudo": 1.35,
    "subclasses": 1.70,
    "subprocess": 1.55,
    "exfiltrate": 1.75,
    "ransomware": 1.90,
    "dcsync": 1.85,
    "kerberoast": 1.80,
    "pass-the-hash": 1.80,
    "invoke-expression": 1.65,
    "iex": 1.55,
    "downloadstring": 1.65,
    "base64": 1.35,
    "override": 1.45,
    "ignore": 1.35,
    "drop": 1.25,
    "nc": 1.30,
    "curl": 1.10,
}

_PRIV_ESC_KEYWORDS = {
    "mimikatz", "sekurlsa", "lsass", "sudo", "chmod", "/etc/shadow", "ntds.dit", "dcsync", "system"
}
_LATERAL_C2_KEYWORDS = {
    "psexec", "wmic", "cobaltstrike", "beacon", "meterpreter", "downloadstring", "kerberoast", "smb"
}
_OBFUSCATION_PATTERN = re.compile(
    r"(?:-enc|-encodedcommand|base64|frombase64string|[A-Za-z0-9+/]{32,}={0,2})", re.IGNORECASE)


class SOCTelemetryFeatureExtractor:
    """Extracts 8D numerical feature vectors and PyTorch token tensors from raw SIEM telemetry."""

    def __init__(self) -> None:
        self.vocab_words = list(SOC_ADVERSARIAL_TOKENS.keys())
        self.word_to_idx = {w: idx + 1 for idx,
                            w in enumerate(self.vocab_words)}

    def extract_8d_vector(
        self,
        raw_log: str,
        network_bytes_out: int = 48500,
        failed_auth_count: int = 0,
        process_entropy_score: float = 4.1,
    ) -> np.ndarray:
        """Transform raw log text and flow metadata into a normalized 8D float32 feature vector."""
        lower_log = raw_log.lower()
        tokens = re.findall(r"[a-z0-9_./-]+", lower_log)
        num_tokens = max(len(tokens), 1)

        log_length_norm = min(len(raw_log) / 600.0, 1.5)

        suspicious_hits = sum(
            weight for kw, weight in SOC_ADVERSARIAL_TOKENS.items() if kw in lower_log
        )
        suspicious_token_density = min(
            suspicious_hits / max(num_tokens * 0.35, 1.0), 1.5)

        network_bytes_log_norm = min(math.log1p(
            max(network_bytes_out, 0)) / 16.0, 1.5)
        failed_auth_norm = min(failed_auth_count / 20.0, 1.5)
        process_entropy_norm = min(max(process_entropy_score, 0.0) / 8.0, 1.2)

        priv_hits = sum(1 for kw in _PRIV_ESC_KEYWORDS if kw in lower_log)
        privilege_escalation_score = min(priv_hits * 0.45, 1.5)

        lat_hits = sum(1 for kw in _LATERAL_C2_KEYWORDS if kw in lower_log)
        lateral_movement_c2_score = min(lat_hits * 0.45, 1.5)

        obf_matches = len(_OBFUSCATION_PATTERN.findall(raw_log))
        obfuscation_indicator_score = min(
            (obf_matches * 0.55) + (0.45 if process_entropy_score >= 5.2 else 0.0),
            1.5,
        )

        return np.array(
            [
                log_length_norm,
                suspicious_token_density,
                network_bytes_log_norm,
                failed_auth_norm,
                process_entropy_norm,
                privilege_escalation_score,
                lateral_movement_c2_score,
                obfuscation_indicator_score,
            ],
            dtype=np.float32,
        )

    def tokenize_for_pytorch(
        self, raw_log: str, max_seq_len: int = 48
    ) -> tuple[list[str], torch.Tensor]:
        """Convert raw log into token strings and a PyTorch LongTensor of token IDs."""
        tokens = re.findall(r"[a-z0-9_./-]+", raw_log.lower())[:max_seq_len]
        if not tokens:
            tokens = ["benign"]

        token_ids: list[int] = []
        for tok in tokens:
            clean = tok.strip("._/")
            if clean in self.word_to_idx:
                token_ids.append(self.word_to_idx[clean])
            elif tok in self.word_to_idx:
                token_ids.append(self.word_to_idx[tok])
            else:
                digest = int(hashlib.md5(
                    clean.encode("utf-8")).hexdigest(), 16)
                token_ids.append(40 + (digest % 1950))

        return tokens, torch.tensor([token_ids], dtype=torch.long)

    @staticmethod
    def generate_soc_training_dataframe(
        n_samples: int = 1000, seed: int = 42
    ) -> tuple[pd.DataFrame, np.ndarray]:
        """
        Generate a deterministic, stratified Pandas DataFrame of benign vs. malicious
        SOC telemetry vectors for training XGBoost, IsolationForest, and PyTorch Autoencoder.
        """
        rng = np.random.default_rng(seed)
        n_benign = int(n_samples * 0.65)
        n_attack = n_samples - n_benign

        # Benign baseline telemetry distribution (low suspicious density, normal entropy)
        benign_matrix = np.column_stack(
            [
                rng.uniform(0.08, 0.45, n_benign),  # log_length_norm
                rng.uniform(0.00, 0.15, n_benign),  # suspicious_token_density
                rng.uniform(0.15, 0.65, n_benign),  # network_bytes_log_norm
                rng.uniform(0.00, 0.15, n_benign),  # failed_auth_norm
                rng.uniform(0.30, 0.58, n_benign),  # process_entropy_norm
                # privilege_escalation_score
                rng.uniform(0.00, 0.10, n_benign),
                rng.uniform(0.00, 0.10, n_benign),  # lateral_movement_c2_score
                # obfuscation_indicator_score
                rng.uniform(0.00, 0.12, n_benign),
            ]
        ).astype(np.float32)

        # Multi-stage APT & C2 attack telemetry distribution
        attack_matrix = np.column_stack(
            [
                rng.uniform(0.30, 1.35, n_attack),  # log_length_norm
                rng.uniform(0.45, 1.45, n_attack),  # suspicious_token_density
                rng.uniform(0.55, 1.40, n_attack),  # network_bytes_log_norm
                rng.uniform(0.20, 1.40, n_attack),  # failed_auth_norm
                rng.uniform(0.62, 1.05, n_attack),  # process_entropy_norm
                # privilege_escalation_score
                rng.uniform(0.40, 1.45, n_attack),
                rng.uniform(0.40, 1.45, n_attack),  # lateral_movement_c2_score
                # obfuscation_indicator_score
                rng.uniform(0.35, 1.45, n_attack),
            ]
        ).astype(np.float32)

        features = np.vstack([benign_matrix, attack_matrix])
        labels = np.concatenate(
            [np.zeros(n_benign, dtype=np.int32),
             np.ones(n_attack, dtype=np.int32)]
        )

        df = pd.DataFrame(features, columns=FEATURE_COLUMNS)
        return df, labels


soc_feature_extractor = SOCTelemetryFeatureExtractor()
