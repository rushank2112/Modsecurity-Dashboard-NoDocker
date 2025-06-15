# parser.py

import re
from datetime import datetime
from typing import List, Optional
from models import LogEntry, RuleMessage


def parse_modsec_log(file_path: str) -> List[LogEntry]:
    """
    Parse ModSecurity audit log file and extract log entries with rule messages.
    Returns a list of LogEntry objects.
    """
    try:
        with open(file_path, "r") as file:
            content = file.read()
    except (IOError, FileNotFoundError) as e:
        print(f"Error reading log file: {e}")
        return []

    # Split on audit log transaction start lines (section A)
    transactions = re.split(r'--[a-f0-9]+-A--\n', content)
    transactions = [t.strip() for t in transactions if t.strip()]

    log_entries = []

    for t in transactions:
        # Extract timestamp, source IP/port, and dest IP/port from Section A
        section_a = re.search(
            r'^\[(.*?)\]\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)',
            t,
            re.MULTILINE
        )

        if not section_a:
            continue

        timestamp_str = section_a.group(1).split()[0]
        source_ip = section_a.group(2)
        source_port = int(section_a.group(3))
        dest_ip = section_a.group(4)
        dest_port = int(section_a.group(5))  # ✅ Use this for correct port info

        try:
            timestamp = parse_timestamp(timestamp_str)
        except ValueError:
            print(f"Invalid timestamp format: {timestamp_str}")
            continue

        method, path = extract_request_details(t)
        status = extract_status_code(t)
        rule_messages = extract_rule_messages(t)

        log_entry = LogEntry(
            timestamp=timestamp,
            ip_address=source_ip,  # You can change to dest_ip if needed
            port=dest_port,        # ✅ Correct destination port (e.g., 8880, 8881)
            method=method or "",
            path=path or "",
            status=status or 0,
            rule_messages=rule_messages
        )
        log_entries.append(log_entry)

    return log_entries


def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse ModSecurity timestamp string into datetime object"""
    try:
        return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S.%f')
    except ValueError:
        return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')


def extract_request_details(transaction: str) -> (Optional[str], Optional[str]):
    """Extract HTTP method and path from transaction"""
    request_match = re.search(
        r'--[a-f0-9]+-B--\n([A-Z]+) (.+?) HTTP/',
        transaction,
        re.DOTALL
    )
    if request_match:
        return request_match.group(1), request_match.group(2)
    return None, None


def extract_status_code(transaction: str) -> Optional[int]:
    """Extract HTTP status code from transaction"""
    response_match = re.search(
        r'--[a-f0-9]+-F--\nHTTP/[\d\.]+ (\d+)',
        transaction
    )
    if response_match:
        try:
            return int(response_match.group(1))
        except ValueError:
            return None
    return None


def extract_rule_messages(transaction: str) -> List[RuleMessage]:
    """Extract all rule messages from transaction"""
    messages = []
    pattern = re.compile(
        r'Message: (.*?)\s*'
        r'\[file "(.*?)"\]\s*'
        r'\[line "(.*?)"\]\s*'
        r'\[id "(.*?)"\]\s*'
        r'\[msg "(.*?)"\]'
        r'(\s*\[data "(.*?)"\])?'
        r'(\s*\[severity "(.*?)"\])?',
        re.DOTALL
    )

    for match in re.finditer(pattern, transaction):
        rule_msg = RuleMessage(
            rule_id=match.group(4),
            rule_msg=match.group(5),
            rule_data=match.group(7) if match.group(7) else None,
            rule_severity=match.group(9) if match.group(9) else None
        )
        messages.append(rule_msg)

    return messages


def extract_rule_descriptions_from_log(file_path: str) -> dict:
    """Parse log and return a map of rule_id → msg (clean description)."""
    rule_descriptions = {}
    try:
        with open(file_path, "r") as f:
            content = f.read()
    except Exception as e:
        print(f"Failed to read log for rule descriptions: {e}")
        return {}

    pattern = re.compile(
        r'\[id\s+"(\d+)"\]\s*\[msg\s+"(.*?)"\]',
        re.DOTALL
    )

    for match in re.finditer(pattern, content):
        rule_id = match.group(1)
        msg = match.group(2)
        if rule_id not in rule_descriptions:
            rule_descriptions[rule_id] = msg

    return rule_descriptions
