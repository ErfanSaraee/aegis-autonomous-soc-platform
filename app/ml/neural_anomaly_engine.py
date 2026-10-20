"""Hybrid Deep Learning & Classical ML SOC Engine: PyTorch Autoencoder/Attention, XGBoost & IsolationForest."""

import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from app.core.logging import get_logger
from app.ml.feature_extractor import (
    FEATURE_COLUMNS,
    SOC_ADVERSARIAL_TOKENS,
    soc_feature_extractor,
)
from app.models.soc_models import IncidentSeverity
from app.schemas.soc import NeuralAnomalyReport

logger = get_logger(__name__)


class SOCAutoencoderAttentionNet(nn.Module):
    """
    Dual-branch PyTorch Deep Learning architecture for SIEM Telemetry:
    1. Deep Telemetry Autoencoder (8D -> 16D -> 4D bottleneck -> 16D -> 8D) computing reconstruction anomaly error.
    2. Multi-Head Self-Attention over tokenized log sequences highlighting salient adversarial commands.
    """

    def __init__(self, vocab_size: int = 2048, embed_dim: int = 32, num_heads: int = 4) -> None:
        super().__init__()
        torch.manual_seed(42)

        # Branch 1: 8D Telemetry Reconstruction Autoencoder
        self.encoder = nn.Sequential(
            nn.Linear(len(FEATURE_COLUMNS), 16),
            nn.GELU(),
            nn.Linear(16, 4),
            nn.GELU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(4, 16),
            nn.GELU(),
            nn.Linear(16, len(FEATURE_COLUMNS)),
        )

        # Branch 2: Multi-Head Self-Attention Log Sequence Analyzer
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.attention = nn.MultiheadAttention(
            embed_dim=embed_dim,
            num_heads=num_heads,
            batch_first=True,
        )
        self.layer_norm = nn.LayerNorm(embed_dim)
        self.attn_Readout = nn.Linear(embed_dim, 1)

        self._initialize_weights()

    def _initialize_weights(self) -> None:
        with torch.no_grad():
            nn.init.normal_(self.embedding.weight, mean=0.0, std=0.1)
            self.embedding.weight[0].zero_()
            for idx in range(1, len(SOC_ADVERSARIAL_TOKENS) + 1):
                self.embedding.weight[idx, :8] += 1.55
            nn.init.uniform_(self.attn_Readout.weight, 0.20, 0.45)
            self.attn_Readout.bias.fill_(-0.85)

    def forward(
        self, features_8d: torch.Tensor, token_ids: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Return:
        - reconstructed_8d: Autoencoder reconstruction of input 8D vector
        - attention_prob: Self-Attention threat score in [0, 1]
        - attn_weights: Token-level self-attention matrix
        """
        latent = self.encoder(features_8d)
        reconstructed_8d = self.decoder(latent)

        embeds = self.embedding(token_ids)
        attn_out, attn_weights = self.attention(
            embeds, embeds, embeds, need_weights=True, average_attn_weights=True
        )
        pooled = self.layer_norm(embeds + attn_out).mean(dim=1)
        # Boost attention logit with suspicious token density feature (index 1)
        density_boost = features_8d[:, 1:2] * 2.4 + \
            features_8d[:, 5:6] * 1.3 + features_8d[:, 6:7] * 1.3
        attention_prob = torch.sigmoid(
            self.attn_Readout(pooled) + density_boost)

        return reconstructed_8d, attention_prob, attn_weights


class NeuralSOCAnomalyEngine:
    """Orchestrates PyTorch Autoencoder/Attention, XGBoost Classifier, and Scikit-Learn IsolationForest."""

    def __init__(self) -> None:
        self.pytorch_net = SOCAutoencoderAttentionNet()
        self.xgb_classifier = XGBClassifier(
            n_estimators=90,
            max_depth=4,
            learning_rate=0.08,
            eval_metric="logloss",
            random_state=42,
        )
        self.isolation_pipeline = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "isoforest",
                    IsolationForest(
                        n_estimators=100,
                        contamination=0.12,
                        random_state=42,
                    ),
                ),
            ]
        )
        self._benign_centroid: np.ndarray = np.zeros(
            len(FEATURE_COLUMNS), dtype=np.float32)
        self._train_and_calibrate_models()

    def _train_and_calibrate_models(self) -> None:
        """Train PyTorch Autoencoder on benign baseline and fit XGBoost + IsolationForest."""
        df, labels = soc_feature_extractor.generate_soc_training_dataframe(
            n_samples=1000, seed=42)
        benign_df = df[labels == 0]
        self._benign_centroid = benign_df.to_numpy(
            dtype=np.float32).mean(axis=0)

        # 1. Fit XGBoost supervised classifier on full stratified dataset
        self.xgb_classifier.fit(df, labels)

        # 2. Fit IsolationForest unsupervised pipeline on benign baseline traffic
        self.isolation_pipeline.fit(benign_df)

        # 3. Train PyTorch Autoencoder on benign telemetry vectors (fast 35-epoch warmup)
        self.pytorch_net.train()
        optimizer = torch.optim.AdamW(
            list(self.pytorch_net.encoder.parameters()) +
            list(self.pytorch_net.decoder.parameters()),
            lr=0.015,
        )
        criterion = nn.MSELoss()
        benign_tensor = torch.tensor(benign_df.to_numpy(
            dtype=np.float32), dtype=torch.float32)

        for _ in range(35):
            optimizer.zero_grad()
            recon = self.pytorch_net.decoder(
                self.pytorch_net.encoder(benign_tensor))
            loss = criterion(recon, benign_tensor)
            loss.backward()
            optimizer.step()

        self.pytorch_net.eval()
        logger.info(
            "AEGIS Neural SOC Engine (PyTorch Autoencoder/Attention + XGBoost + IsolationForest) calibrated.")

    def evaluate_telemetry(
        self,
        raw_log: str,
        network_bytes_out: int = 48500,
        failed_auth_count: int = 0,
        process_entropy_score: float = 4.1,
    ) -> NeuralAnomalyReport:
        """Run multi-model inference on incoming SIEM telemetry and return a unified NeuralAnomalyReport."""
        vec_8d = soc_feature_extractor.extract_8d_vector(
            raw_log=raw_log,
            network_bytes_out=network_bytes_out,
            failed_auth_count=failed_auth_count,
            process_entropy_score=process_entropy_score,
        )
        tokens, token_tensor = soc_feature_extractor.tokenize_for_pytorch(
            raw_log)
        feat_tensor = torch.from_numpy(vec_8d).unsqueeze(0)

        with torch.no_grad():
            recon_t, attn_prob_t, attn_weights_t = self.pytorch_net(
                feat_tensor, token_tensor)
            raw_mse = float(torch.mean((feat_tensor - recon_t) ** 2).item())

        # Normalize reconstruction error into [0.0, 1.0] scale
        centroid_dist = float(np.mean((vec_8d - self._benign_centroid) ** 2))
        recon_error = round(
            min((raw_mse * 1.8) + (centroid_dist * 0.85), 1.0), 4)
        attn_score = round(float(attn_prob_t.item()), 4)

        # Extract top salient tokens from Multi-Head Attention + SOC lexicon weights
        attn_row = attn_weights_t[0].mean(dim=0).tolist()
        token_salience: dict[str, float] = {}
        for tok, weight in zip(tokens, attn_row):
            clean = tok.strip("._/")
            lex_boost = SOC_ADVERSARIAL_TOKENS.get(
                clean, SOC_ADVERSARIAL_TOKENS.get(tok, 0.08)
            )
            score = round(float(weight * 0.45 + lex_boost * 0.55), 4)
            if tok not in token_salience or score > token_salience[tok]:
                token_salience[tok] = score

        top_tokens = dict(
            sorted(token_salience.items(),
                   key=lambda item: item[1], reverse=True)[:6]
        )

        # XGBoost & IsolationForest inference
        import pandas as pd

        row_df = pd.DataFrame([vec_8d], columns=FEATURE_COLUMNS)
        xgb_prob = round(
            float(self.xgb_classifier.predict_proba(row_df)[0][1]), 4)
        iso_pred = int(self.isolation_pipeline.predict(row_df)[0])
        is_outlier = iso_pred == -1 or recon_error >= 0.52

        # Compute composite anomaly score in [0.0, 1.0]
        composite = round(
            min(
                max(
                    (xgb_prob * 0.42)
                    + (attn_score * 0.33)
                    + (recon_error * 0.25)
                    + (0.08 if is_outlier else 0.0),
                    0.0,
                ),
                1.0,
            ),
            4,
        )

        if composite >= 0.80:
            severity = IncidentSeverity.P0_CRITICAL
        elif composite >= 0.62:
            severity = IncidentSeverity.P1_HIGH
        elif composite >= 0.42:
            severity = IncidentSeverity.P2_MEDIUM
        elif composite >= 0.25:
            severity = IncidentSeverity.P3_LOW
        else:
            severity = IncidentSeverity.BENIGN

        return NeuralAnomalyReport(
            pytorch_reconstruction_error=recon_error,
            pytorch_attention_score=attn_score,
            top_salient_log_tokens=top_tokens,
            xgboost_threat_probability=xgb_prob,
            isolation_forest_anomaly=is_outlier,
            composite_anomaly_score=composite,
            predicted_severity=severity,
        )


neural_anomaly_engine = NeuralSOCAnomalyEngine()
