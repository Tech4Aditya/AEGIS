import os

DATABASE_URL = os.getenv("DATABASE_URL", "")
REDIS_URL = os.getenv("REDIS_URL", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "")
