import re
from datetime import datetime
from fastapi import FastAPI, Request, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, StreamingResponse, Response, RedirectResponse
from collections import namedtuple
import os
import csv
from io import StringIO
from weasyprint import HTML

app = FastAPI()
templates = Jinja2Templates(directory="templates")

LogEntry = namedtuple("LogEntry", ["timestamp", "ip_address", "port", "method", "path", "status"])

PER_PAGE = 20
LOG_FILE_PATH = "/var/log/apache2/modsec_audit.log"

def parse_modsec_log(file_path):
    if not os.path.isfile(file_path) or not os.access(file_path, os.R_OK):
        return [], 0, 0, 0

    with open(file_path, "r") as file:
        content = file.read()

    transactions = re.split(r'--[a-f0-9]+-A--\n', content)
    transactions = [t.strip() for t in transactions if t.strip()]

    logs = []
    total_requests = 0
    blocked_requests = 0
    attack_attempts = 0

    for t in transactions:
        section_a = re.search(r'^\[(.*?)\].*?(\d{1,3}(?:\.\d{1,3}){3}) (\d+)', t, re.MULTILINE)
        if section_a:
            timestamp_str = section_a.group(1).split()[0]
            fallback_ip = section_a.group(2)
            fallback_port = section_a.group(3)
            try:
                timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S.%f')
            except ValueError:
                timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S')
        else:
            timestamp = None
            fallback_ip = "unknown"
            fallback_port = "unknown"

        host_match = re.search(r'Host:\s*([^\s:]+):(\d+)', t)
        if host_match:
            ip = host_match.group(1)
            port = host_match.group(2)
        else:
            ip = fallback_ip
            port = fallback_port

        request_match = re.search(r'--[a-f0-9]+-B--\n([A-Z]+) (.+?) HTTP/', t, re.DOTALL)
        method = request_match.group(1) if request_match else None
        path = request_match.group(2) if request_match else None

        response_match = re.search(r'--[a-f0-9]+-F--\nHTTP/[\d\.]+ (\d+)', t)
        status = int(response_match.group(1)) if response_match else None

        total_requests += 1

        # ModSecurity rule violations (Blocked Requests) - usually 406, 414, etc.
        if status in (406, 414):
            blocked_requests += 1
        # Attack Attempts explicitly 403
        if status == 403:
            attack_attempts += 1

        logs.append(LogEntry(timestamp, ip, port, method, path, status))

    return logs, total_requests, blocked_requests, attack_attempts

def filter_logs(log_entries, log_type: str):
    if log_type == "normal":
        # Normal traffic: status codes 200–399, 401, 404, etc. (not blocked or attack)
        filtered = [e for e in log_entries if e.status and (
            (200 <= e.status < 400) or e.status in (401, 404)
        )]
    elif log_type == "blocked":
        # Blocked requests: status codes like 406, 414 (rule violations but not explicit attack)
        filtered = [e for e in log_entries if e.status in (406, 414)]
    elif log_type == "attack":
        # Attack attempts: explicitly 403
        filtered = [e for e in log_entries if e.status == 403]
    elif log_type == "total":
        filtered = log_entries
    else:
        filtered = []
    return filtered

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    log_entries, total_requests, blocked_requests, attack_attempts = parse_modsec_log(LOG_FILE_PATH)
    normal_traffic = total_requests - blocked_requests - attack_attempts
    recent_logs = list(reversed(log_entries))[:50]
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "normal_traffic": normal_traffic,
        "blocked_requests": blocked_requests,
        "attack_attempts": attack_attempts,
        "recent_logs": recent_logs
    })

@app.get("/logs/{log_type}", response_class=HTMLResponse)
async def logs_page(request: Request, log_type: str, page: int = 1):
    log_entries, _, _, _ = parse_modsec_log(LOG_FILE_PATH)
    filtered = filter_logs(log_entries, log_type)

    title_map = {
        "normal": "Normal Traffic",
        "blocked": "Blocked Requests",
        "attack": "Attack Attempts",
        "total": "Total Requests"
    }
    title = title_map.get(log_type, "Unknown Log Type")

    total_entries = len(filtered)
    total_pages = (total_entries + PER_PAGE - 1) // PER_PAGE or 1
    page = max(1, min(page, total_pages))
    start = (page - 1) * PER_PAGE
    end = start + PER_PAGE
    page_entries = filtered[start:end]

    return templates.TemplateResponse("logs.html", {
        "request": request,
        "entries": page_entries,
        "page": page,
        "has_next": page < total_pages,
        "has_prev": page > 1,
        "log_type": log_type,
        "title": title,
        "total_pages": total_pages,
    })

@app.get("/export/csv")
async def export_csv(log_type: str = Query("total")):
    log_entries, _, _, _ = parse_modsec_log(LOG_FILE_PATH)
    filtered = filter_logs(log_entries, log_type)

    def generate():
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["Timestamp", "IP", "Port", "Method", "Path", "Status"])
        for entry in filtered:
            writer.writerow([
                entry.timestamp.strftime('%Y-%m-%d %H:%M:%S') if entry.timestamp else '',
                entry.ip_address,
                entry.port,
                entry.method,
                entry.path,
                entry.status
            ])
        buffer.seek(0)
        return buffer.read()

    filename = f"modsec_logs_{log_type}.csv"
    return StreamingResponse(iter([generate()]), media_type="text/csv", headers={
        "Content-Disposition": f"attachment; filename={filename}"
    })

@app.get("/export/pdf")
async def export_pdf(request: Request, log_type: str = Query("total")):
    log_entries, total_requests, blocked_requests, attack_attempts = parse_modsec_log(LOG_FILE_PATH)
    filtered = filter_logs(log_entries, log_type)

    title_map = {
        "total": "Total Requests",
        "normal": "Normal Traffic",
        "blocked": "Blocked Requests",
        "attack": "Attack Attempts"
    }
    title = title_map.get(log_type, "Unknown Log Type")

    html_content = templates.get_template("logs_pdf.html").render({
        "request": request,
        "entries": filtered,
        "title": title,
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "attack_attempts": attack_attempts,
    })

    pdf = HTML(string=html_content).write_pdf()
    filename = f"modsec_report_{log_type}.pdf"
    return Response(content=pdf, media_type="application/pdf", headers={
        "Content-Disposition": f"attachment; filename={filename}"
    })

@app.post("/reset-logs")
def reset_logs():
    with open(LOG_FILE_PATH, "w") as f:
        f.truncate(0)
    return RedirectResponse(url="/", status_code=303)
