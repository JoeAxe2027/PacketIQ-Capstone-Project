from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import ollama

app = FastAPI(title="PacketIQ - Gemma 3 AI Analyzer")

# Request model
class PacketAnalysisRequest(BaseModel):
    packet_data: str
    system_prompt: str = "You are a network security expert. Analyze the following packet data for security threats or protocol errors."

@app.post("/analyze")
async def analyze_packet(request: PacketAnalysisRequest):
    try:
        # Standard call for gemma3:4b
        response = ollama.generate(
            model='gemma3:4b',
            prompt=f"{request.system_prompt}\n\nData: {request.packet_data}"
        )
        
        return {
            "model": "gemma3:4b",
            "analysis": response['response'],
            "context_length": len(request.packet_data)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    # Using 8001 to avoid conflict with other services
    uvicorn.run(app, host="0.0.0.0", port=8001)