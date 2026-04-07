import os
import requests


class OllamaClient:
    def __init__(self, base_url=None, model=None, timeout=None, num_ctx=None):
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.2")
        self.timeout = int(timeout or os.getenv("OLLAMA_TIMEOUT", "120"))
        self.num_ctx = int(num_ctx or os.getenv("OLLAMA_NUM_CTX", "2048"))

    def chat(self, messages, stream=False):
        print(f"DEBUG: OllamaClient base_url={self.base_url}")
        print(f"DEBUG: OllamaClient model={self.model}")
        prompt = "\n".join(
            f"{m.get('role', 'user')}: {m.get('content', '')}" for m in messages
        )

        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "prompt": prompt,
                "stream": stream,
                "options": {
                    "num_ctx": self.num_ctx
                }
            },
            timeout=self.timeout
        )
        response.raise_for_status()
        data = response.json()

        return {
            "message":{
                "role": "assistant",
                "content": data.get("response", "")
            },
            "raw": data

        }