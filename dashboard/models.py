from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict
from enum import Enum

# Existing models (unchanged)
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

# New models for rule management
class RuleAction(str, Enum):
    BLOCK = "block"
    MONITOR = "monitor"
    DISABLED = "disabled"

class RuleCategory(str, Enum):
    PROTOCOL = "protocol"
    XSS = "xss"
    SQLI = "sqli"
    LFI = "lfi"
    RFI = "rfi"
    RCE = "rce"
    PHP = "php"
    JAVA = "java"
    SCANNER = "scanner"
    DOS = "dos"
    GENERIC = "generic"

@dataclass
class ModSecRule:
    """Represents a ModSecurity rule with configurable actions"""
    rule_id: str
    file_name: str
    description: str
    default_action: RuleAction = RuleAction.BLOCK
    current_action: RuleAction = RuleAction.BLOCK
    severity: Optional[str] = None
    category: RuleCategory = RuleCategory.GENERIC
    last_modified: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)

@dataclass
class RuleOverride:
    """Represents a temporary override of a rule's action"""
    rule_id: str
    original_action: RuleAction
    override_action: RuleAction
    expires_at: Optional[datetime] = None
    comment: Optional[str] = None

@dataclass
class RuleStats:
    """Tracks statistics about rule triggers"""
    rule_id: str
    total_hits: int = 0
    last_24h_hits: int = 0
    last_hit: Optional[datetime] = None
    blocked_count: int = 0
    monitored_count: int = 0

@dataclass
class RuleSet:
    """Collection of rules with management capabilities"""
    rules: Dict[str, ModSecRule] = field(default_factory=dict)
    overrides: Dict[str, RuleOverride] = field(default_factory=dict)
    stats: Dict[str, RuleStats] = field(default_factory=dict)

    def add_rule(self, rule: ModSecRule):
        self.rules[rule.rule_id] = rule
        if rule.rule_id not in self.stats:
            self.stats[rule.rule_id] = RuleStats(rule_id=rule.rule_id)

    def update_rule_action(self, rule_id: str, action: RuleAction):
        if rule_id in self.rules:
            self.rules[rule_id].current_action = action
            return True
        return False

    def add_override(self, override: RuleOverride):
        if override.rule_id in self.rules:
            self.overrides[override.rule_id] = override
            self.rules[override.rule_id].current_action = override.override_action
            return True
        return False

    def record_trigger(self, rule_message: RuleMessage, was_blocked: bool):
        if rule_message.rule_id in self.stats:
            stats = self.stats[rule_message.rule_id]
            stats.total_hits += 1
            stats.last_hit = datetime.now()
            if was_blocked:
                stats.blocked_count += 1
            else:
                stats.monitored_count += 1
