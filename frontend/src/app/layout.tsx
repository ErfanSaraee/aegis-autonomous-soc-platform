import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
    title: "AEGIS Autonomous SOC & Guardrailed SOAR Command Center",
    description:
        "Multi-Agent Cyber Defense Platform powered by LangGraph, PyTorch, XGBoost, Hybrid MITRE ATT&CK RAG, CrewAI, DSPy, and FastMCP.",
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en" className="dark">
            <body className="min-h-screen bg-[#060911] text-slate-100 antialiased selection:bg-emerald-500/30 selection:text-emerald-200">
                {children}
            </body>
        </html>
    );
}