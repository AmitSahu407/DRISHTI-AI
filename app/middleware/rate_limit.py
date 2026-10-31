"""Simple per-process development limiter. Use Redis-backed limits behind multiple workers."""
from collections import defaultdict, deque
from time import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from app.config import settings

class RateLimitMiddleware(BaseHTTPMiddleware):
    buckets=defaultdict(deque)
    async def dispatch(self,request,call_next):
        if request.url.path in ("/healthz","/"): return await call_next(request)
        key=request.client.host if request.client else "unknown"
        now=time(); q=self.buckets[key]
        while q and q[0] < now-60: q.popleft()
        if len(q)>=settings.rate_limit_per_minute:
            return JSONResponse({"detail":"Rate limit exceeded"},status_code=429)
        q.append(now)
        return await call_next(request)
