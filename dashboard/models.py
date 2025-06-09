# models.py

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class RuleMessage:
    rule_id: str
    rule_msg: str
    rule_severity: Optional[str] = None
    rule_data: Optional[str] = None


@dataclass
class LogEntry:
    timestamp: datetime
    ip_address: str
    port: int
    method: str
    path: str
    status: int
    rule_messages: List[RuleMessage] = field(default_factory=list)
