"""科技战略协作基础服务的服务端基础包。"""

from .incident_service import IncidentService
from .service import DomainService

__all__ = ["DomainService", "IncidentService"]
