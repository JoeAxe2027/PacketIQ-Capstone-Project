def build_alert_prompt(alert_type: str, evidence: str) -> str:
    return f"""
You are a network forensics analyst.

Alert Type:
{alert_type}

Evidence:
{evidence}

Tasks:
1. Explain what this activity means.
2. State whether it appears suspicious.
3. Give a severity level: low, medium, or high.
4. Suggest 3 next investigation steps.
5. Use only the evidence provided.
""".strip()