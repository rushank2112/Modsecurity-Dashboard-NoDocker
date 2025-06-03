import re
from datetime import datetime
from models import LogEntry
from database import SessionLocal

def parse_modsec_log(file_path):
    with open(file_path, "r") as file:
        content = file.read()

    # Split by start of transaction: --<id>-A--
    transactions = re.split(r'--[a-f0-9]+-A--\n', content)
    transactions = [t.strip() for t in transactions if t.strip()]

    print(f"Total entries found: {len(transactions)}")

    db = SessionLocal()

    for t in transactions:
        # Extract timestamp and IP from section A
        section_a = re.search(r'^\[(.*?)\].*?(\d{1,3}(?:\.\d{1,3}){3})', t, re.MULTILINE)
        if section_a:
            timestamp_str = section_a.group(1).split()[0]
            ip = section_a.group(2)
            try:
                timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S.%f')
            except ValueError:
                timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
        else:
            timestamp = None
            ip = "unknown"

        # Extract HTTP method and path from section B
        request_match = re.search(r'--[a-f0-9]+-B--\n([A-Z]+) (.+?) HTTP/', t, re.DOTALL)
        method = request_match.group(1) if request_match else None
        path = request_match.group(2) if request_match else None

        # Extract status from section F
        response_match = re.search(r'--[a-f0-9]+-F--\nHTTP/[\d\.]+ (\d+)', t)
        status = int(response_match.group(1)) if response_match else None

        # Save to DB only if timestamp, ip, and status are found (basic sanity check)
        if timestamp and ip and status:
            entry = LogEntry(
                timestamp=timestamp,
                ip_address=ip,
                method=method,
                path=path,
                status=status
            )
            db.add(entry)
        else:
            print("Skipping malformed entry.")

    db.commit()
    db.close()
