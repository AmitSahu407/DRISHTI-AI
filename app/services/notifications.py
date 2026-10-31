from app.models.entities import Alert

def create_dashboard_notification(db, incident):
    alert = Alert(incident_id=incident.id, channel="dashboard",
                  delivery_status="queued",
                  message=f"{incident.event_type} at {incident.location} ({incident.severity.value})")
    db.add(alert)
    return alert

# Email and Telegram adapters belong here. Keep provider credentials in environment variables.
# Queue delivery through Celery/RQ/Arq in production; do not block incident creation on email APIs.
