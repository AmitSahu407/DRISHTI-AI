from app.models.entities import SystemLog

def write_log(db, action: str, resource_type: str, actor_id=None, resource_id=None, details=None, ip_address=None):
    db.add(SystemLog(actor_id=actor_id, action=action, resource_type=resource_type,
                     resource_id=str(resource_id) if resource_id is not None else None,
                     details=details or {}, ip_address=ip_address))
