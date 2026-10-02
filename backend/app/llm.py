from __future__ import annotations
import json, httpx
from .config import LLM_BASE_URL, LLM_API_KEY, LLM_MODEL

class LLMAdapter:
    def enabled(self):
        return bool(LLM_BASE_URL and LLM_API_KEY and LLM_MODEL)

    async def structured(self, system, user, fallback):
        if not self.enabled():
            return fallback
        try:
            url=LLM_BASE_URL+"/chat/completions"
            headers={"Authorization":f"Bearer {LLM_API_KEY}","Content-Type":"application/json"}
            body={
              "model":LLM_MODEL,
              "messages":[{"role":"system","content":system},{"role":"user","content":user}],
              "temperature":0.1,
              "response_format":{"type":"json_object"}
            }
            async with httpx.AsyncClient(timeout=25) as c:
                r=await c.post(url,headers=headers,json=body)
                r.raise_for_status()
                content=r.json()["choices"][0]["message"]["content"]
                return json.loads(content)
        except Exception as e:
            out=dict(fallback)
            out["_llm_error"]=str(e)
            return out

llm=LLMAdapter()
