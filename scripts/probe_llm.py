import asyncio
from neurotrace.llm import get_provider
from neurotrace.llm.base import LLMRequest

async def main():
    p = get_provider()
    print("provider=", getattr(p, "name", type(p).__name__))
    print("model=", getattr(p, "default_model", getattr(p, "model", "?")))
    req = LLMRequest(
        system="You are a JSON API. Reply with only JSON.",
        user='Return exactly: {"ok": true}',
        json_mode=True,
        max_tokens=64,
    )
    try:
        resp = await p.chat(req)
        print("text=", (resp.text or "")[:300])
        print("parsed=", resp.parsed)
        print("usage=", resp.usage)
        print("STATUS=OK")
    except Exception as e:
        print("STATUS=FAIL", type(e).__name__, e)

if __name__ == "__main__":
    asyncio.run(main())
