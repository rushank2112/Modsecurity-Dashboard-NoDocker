import os
import re
import gzip
from datetime import datetime
from typing import List, Optional
from models import LogEntry, RuleMessage

UNPARSED_LOG_PATH = "/var/log/modsec/unparsed_entries.log"

def parse_modsec_log(file_path: str) -> List[LogEntry]:
    """
    Parse ModSecurity audit log file and extract log entries with rule messages.
    Log binary/compressed or undecodable entries to a separate file.
    """
    try:
        with open(file_path, "rb") as file:
            binary_content = file.read()
    except (IOError, FileNotFoundError) as e:
        print(f"Error reading log file: {e}")
        return []

    raw_transactions = re.split(rb'--[a-f0-9]+-A--\n', binary_content)
    raw_transactions = [t.strip() for t in raw_transactions if t.strip()]

    log_entries = []
    skipped_entries = []

    for t in raw_transactions:
        if b'\x1f\x8b' in t:
            skipped_entries.append(t)
            continue

        try:
            transaction = t.decode('utf-8')
        except UnicodeDecodeError:
            skipped_entries.append(t)
            continue

        section_a = re.search(
            r'^\[(.*?)\]\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)',
            transaction,
            re.MULTILINE
        )

        if not section_a:
            continue

        timestamp_str = section_a.group(1).split()[0]
        source_ip = section_a.group(2)
        source_port = int(section_a.group(3))
        dest_ip = section_a.group(4)
        dest_port = int(section_a.group(5))

        try:
            timestamp = parse_timestamp(timestamp_str)
        except ValueError:
            print(f"Invalid timestamp format: {timestamp_str}")
            continue

        method, path = extract_request_details(transaction)
        status = extract_status_code(transaction)
        rule_messages = extract_rule_messages(transaction)

        log_entry = LogEntry(
            timestamp=timestamp,
            ip_address=source_ip,
            port=dest_port,
            method=method or "",
            path=path or "",
            status=status or 0,
            rule_messages=rule_messages
        )
        log_entries.append(log_entry)

    # Write skipped binary/unparsed entries to a file
    if skipped_entries:
        try:
            os.makedirs(os.path.dirname(UNPARSED_LOG_PATH), exist_ok=True)
            with open(UNPARSED_LOG_PATH, "ab") as unparsed_file:
                for entry in skipped_entries:
                    unparsed_file.write(b"--UNPARSED--\n" + entry + b"\n\n")
            print(f"⚠️ {len(skipped_entries)} binary/unparsed entries saved to {UNPARSED_LOG_PATH}")
        except Exception as e:
            print(f"Failed to write unparsed entries: {e}")

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
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
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
