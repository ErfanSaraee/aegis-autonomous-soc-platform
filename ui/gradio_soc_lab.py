"""Interactive Gradio 5 & Plotly SOC Neural Telemetry & AST Sandbox Workbench."""

import asyncio
from pathlib import Path
import sys
from typing import Any

import gradio as gr
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.agents.langgraph_soc_commander import langgraph_soc_commander  # noqa: E402
from app.api.v1.presets import APT_SIMULATION_PRESETS  # noqa: E402
from app.models.soc_models import LLMProviderChoice  # noqa: E402
from app.security.ast_soar_sandbox import soar_ast_sandbox  # noqa: E402


def run_soc_investigation_sync(
    scenario_key: str,
    llm_provider_str: str,
) -> tuple[str, go.Figure, go.Figure, pd.DataFrame, str, dict[str, Any]]:
    """Execute the 7-node LangGraph SOC pipeline and build Plotly telemetry visualizations."""
    preset = APT_SIMULATION_PRESETS.get(
        scenario_key, list(APT_SIMULATION_PRESETS.values())[0]
    )
    req = preset.model_copy(
        update={"preferred_llm_provider": LLMProviderChoice(llm_provider_str)}
    )
    res = asyncio.run(langgraph_soc_commander.investigate_incident(req))

    banner_md = (
        f"### 🛡️ AEGIS Verdict: `{res.severity.value}` | Status: `{res.status.value}`\n"
        f"- **MITRE ATT&CK Attribution:** `{res.mitre_tactic.value}` (`{res.mitre_technique_id}`) | "
        f"**LLM Gateway:** `{res.llm_provider_used.value.upper()}`\n"
        f"- **Composite Anomaly Score:** `{res.neural_anomaly.composite_anomaly_score * 100:.1f}%` "
        f"(PyTorch Recon: `{res.neural_anomaly.pytorch_reconstruction_error * 100:.1f}%`, "
        f"XGBoost Prob: `{res.neural_anomaly.xgboost_threat_probability * 100:.1f}%`)\n"
        f"- **Zero-Trust Log Firewall:** `Injection={res.log_guardrail.log_injection_detected}` | "
        f"`Shannon Entropy={res.log_guardrail.shannon_entropy} bits/char` | "
        f"**DSPy False-Positive Likelihood:** `{res.dspy_calibration.false_positive_likelihood * 100:.1f}%`"
    )

    # Chart 1: PyTorch Multi-Head Self-Attention Salient Log Tokens
    tokens_dict = res.neural_anomaly.top_salient_log_tokens or {"benign": 0.1}
    df_tokens = pd.DataFrame(
        {
            "Log Token": list(tokens_dict.keys()),
            "Attention Salience": list(tokens_dict.values()),
        }
    ).sort_values("Attention Salience", ascending=True)

    fig_attn = px.bar(
        df_tokens,
        x="Attention Salience",
        y="Log Token",
        orientation="h",
        color="Attention Salience",
        color_continuous_scale="Tealgrn",
        title="PyTorch Multi-Head Self-Attention: Top Adversarial Log Tokens",
    )
    fig_attn.update_layout(
        template="plotly_dark",
        height=320,
        coloraxis_showscale=False,
        margin=dict(l=20, r=20, t=45, b=20),
    )

    # Chart 2: Hybrid MITRE ATT&CK RAG (Dense Vector vs. BM25 Lexical vs. RRF)
    mitre_labels = [f"{h.technique_id}" for h in res.cti_rag_hits]
    dense_vals = [h.dense_vector_score for h in res.cti_rag_hits]
    bm25_vals = [min(h.bm25_lexical_score / 10.0, 1.0)
                 for h in res.cti_rag_hits]

    fig_rag = go.Figure(
        data=[
            go.Bar(name="Dense Vector Cosine", x=mitre_labels,
                   y=dense_vals, marker_color="#10B981"),
            go.Bar(name="Normalized BM25 Lexical", x=mitre_labels,
                   y=bm25_vals, marker_color="#38BDF8"),
        ]
    )
    fig_rag.update_layout(
        barmode="group",
        title="Hybrid MITRE ATT&CK Retrieval (Dense Vector vs. BM25 RRF)",
        template="plotly_dark",
        height=320,
        margin=dict(l=20, r=20, t=45, b=20),
    )

    trace_df = pd.DataFrame(
        [
            {
                "Step": step.step_index,
                "LangGraph Node": step.agent_name,
                "Framework": step.framework,
                "Status": step.status,
                "Latency (ms)": step.latency_ms,
                "Telemetry Summary": step.summary,
            }
            for step in res.agent_trace
        ]
    )

    diagnostics_json = {
        "executive_rca_summary": res.executive_rca_summary,
        "crewai_osint_report": res.crewai_osint_report,
        "ast_verification": res.ast_verification.model_dump(mode="json"),
    }

    return (
        banner_md,
        fig_attn,
        fig_rag,
        trace_df,
        res.soar_python_playbook,
        diagnostics_json,
    )


def build_gradio_soc_workbench() -> gr.Blocks:
    """Build the interactive Gradio 5 & Plotly workbench."""
    default_key = "apt29_log_injection_lsass"
    init_md, init_f1, init_f2, init_df, init_code, init_json = (
        run_soc_investigation_sync(default_key, "anthropic")
    )

    with gr.Blocks(title="AEGIS Autonomous SOC — Neural & LangGraph Workbench") as demo:
        gr.Markdown(
            "# 🛡️ AEGIS Autonomous SOC — Neural SIEM, MITRE RAG & LangGraph Workbench\n"
            "**Engines:** `7-Node LangGraph` • `PyTorch Autoencoder & Self-Attention` • `XGBoost & IsolationForest` • "
            "`Hybrid MITRE ATT&CK RRF RAG` • `CrewAI OSINT` • `DSPy Calibration` • `Python AST SOAR Sandbox`"
        )

        with gr.Tabs():
            with gr.TabItem("🚨 1. End-to-End 7-Node LangGraph SOC Investigation"):
                with gr.Row():
                    scenario_dd = gr.Dropdown(
                        choices=list(APT_SIMULATION_PRESETS.keys()),
                        value=default_key,
                        label="Select Enterprise APT or Benign Telemetry Scenario",
                    )
                    provider_dd = gr.Dropdown(
                        choices=["anthropic", "openai",
                                 "gemini", "ollama", "vllm"],
                        value="anthropic",
                        label="Active Multi-Provider LLM Gateway",
                    )
                    run_btn = gr.Button(
                        "🚀 Execute 7-Node LangGraph Investigation",
                        variant="primary",
                    )

                banner_out = gr.Markdown(value=init_md)

                with gr.Row():
                    attn_plot = gr.Plot(value=init_f1)
                    rag_plot = gr.Plot(value=init_f2)

                trace_table = gr.Dataframe(
                    value=init_df,
                    label="7-Node LangGraph Stateful Execution Trace",
                    interactive=False,
                )

                with gr.Row():
                    soar_code_out = gr.Code(
                        value=init_code,
                        language="python",
                        label="AST-Verified Python SOAR Containment Playbook",
                    )
                    diag_json_out = gr.JSON(
                        value=init_json,
                        label="Executive RCA, CrewAI OSINT & AST Verification Report",
                    )

                run_btn.click(
                    fn=run_soc_investigation_sync,
                    inputs=[scenario_dd, provider_dd],
                    outputs=[
                        banner_out,
                        attn_plot,
                        rag_plot,
                        trace_table,
                        soar_code_out,
                        diag_json_out,
                    ],
                )

            with gr.TabItem("🔬 2. Live Python AST SOAR Playbook Sandbox Tester"):
                gr.Markdown(
                    "Test any LLM-generated SOAR Python script against the formal **Python AST Static Verifier** "
                    "(blocks `os`, `subprocess`, `eval`, `exec`, `__subclasses__`, and unbounded `while True` loops)."
                )
                sample_unsafe = (
                    "import subprocess\n"
                    "def unsafe_soar():\n"
                    "    subprocess.popen('rm -rf /')\n"
                    "    escape = ().__class__.__bases__[0].__subclasses__()\n"
                )
                ast_code_in = gr.Code(
                    value=sample_unsafe,
                    language="python",
                    label="Python SOAR Playbook Candidate",
                )
                ast_btn = gr.Button(
                    "🔍 Verify AST Safety Invariants", variant="primary")
                ast_json_out = gr.JSON(
                    value=soar_ast_sandbox.verify_playbook(
                        sample_unsafe).model_dump(mode="json"),
                    label="Formal AST Verification Output",
                )
                ast_btn.click(
                    fn=lambda c: soar_ast_sandbox.verify_playbook(
                        c).model_dump(mode="json"),
                    inputs=[ast_code_in],
                    outputs=[ast_json_out],
                )

    return demo


if __name__ == "__main__":
    workbench = build_gradio_soc_workbench()
    workbench.launch(server_name="127.0.0.1", server_port=7860)
