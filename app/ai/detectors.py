"""MVP simulation adapters. Replace internals with model inference in an isolated worker."""
import random
from datetime import datetime, timezone

def _result(event_type: str):
    return {"event_type": event_type, "confidence": round(random.uniform(.82, .99), 3),
            "detected_at": datetime.now(timezone.utc).isoformat(), "simulated": True}

def detect_crowd(frame=None): return _result("Crowd Alert")
def detect_fall(frame=None): return _result("Fall Detection")
def detect_intrusion(frame=None): return _result("Unauthorized Entry")
