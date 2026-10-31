from sqlalchemy import func
from app.models.entities import Incident, Severity
from datetime import datetime, timedelta, timezone

def calculate_safety_score(db) -> int:
    since = datetime.now(timezone.utc) - timedelta(days=7)
    counts = {row[0]: row[1] for row in db.query(Incident.severity, func.count(Incident.id))
              .filter(Incident.timestamp >= since).group_by(Incident.severity).all()}
    # Weighted, bounded penalties. Tune weights against validated campus data before operational use.
    penalty = counts.get(Severity.low, 0) * 0.2 + counts.get(Severity.medium, 0) * 0.8
    penalty += counts.get(Severity.high, 0) * 2 + counts.get(Severity.critical, 0) * 4
    return max(0, min(100, round(100 - penalty)))
