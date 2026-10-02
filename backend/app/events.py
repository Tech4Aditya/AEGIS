import asyncio, json
from .config import REDIS_URL
try:
    import redis.asyncio as aioredis
except Exception:
    aioredis=None

class EventBus:
    def __init__(self):
        self.clients=set()
        self.redis=None
        if REDIS_URL and aioredis:
            try: self.redis=aioredis.from_url(REDIS_URL,decode_responses=True)
            except: self.redis=None

    async def connect(self,ws):
        await ws.accept(); self.clients.add(ws)

    def disconnect(self,ws): self.clients.discard(ws)

    async def emit(self,payload):
        if self.redis:
            try: await self.redis.publish("aegis.events",json.dumps(payload))
            except: pass
        dead=[]
        for ws in list(self.clients):
            try: await ws.send_json(payload)
            except: dead.append(ws)
        for ws in dead: self.clients.discard(ws)

bus=EventBus()
