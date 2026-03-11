from .client import OllamaClient
from .prompt_builder import build_alert_prompt

client = OllamaClient()

def explain_alert(alert_type: str, evidence: str) -> str:
    prompt = build_alert_prompt(alert_type, evidence)

    messages = [
        {
            "role": "system",
            "content": "You are a cybersecurity analyst. Use only the supplied evidence."
        },
        {
            "role": "user",
            "content": prompt
        }
    ]

    result = client.chat(messages, stream=False)
    return result["message"]["content"]