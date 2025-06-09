import os
import re
import csv
import base64
import shutil
import tempfile
from collections import defaultdict
from datetime import datetime
from io import StringIO
from typing import Optional, List

from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import matplotlib.pyplot as plt
from weasyprint import HTML

from models import LogEntry, RuleMessage
from parser import parse_modsec_log

app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

PER_PAGE = 20
LOG_FILE_PATH = "/var/log/apache2/modsec_audit.log"
LOG_ENTRIES: List[LogEntry] = []

# Removed startup event since we parse on-demand now

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    global LOG_ENTRIES
    LOG_ENTRIES = parse_modsec_log(LOG_FILE_PATH)  # Parse on each request (refresh)
    
    total_requests = len(LOG_ENTRIES)
    blocked_requests = len([entry for entry in LOG_ENTRIES if entry.status in (406, 414)])
    attack_attempts = len([entry for entry in LOG_ENTRIES if entry.status == 403])
    normal_traffic = total_requests - blocked_requests - attack_attempts

    recent_logs = sorted(LOG_ENTRIES, key=lambda x: x.timestamp, reverse=True)[:50]

    status_data = {}
    for entry in LOG_ENTRIES:
        if entry.status is not None:
            status_data[entry.status] = status_data.get(entry.status, 0) + 1
    status_data = [{"status": str(k), "count": v} for k, v in status_data.items()]

    hourly = {}
    for entry in LOG_ENTRIES:
        hour = entry.timestamp.hour
        hourly[hour] = hourly.get(hour, 0) + 1
    hourly_data = [{"hour": h, "count": c} for h, c in hourly.items()]

    ip_counts = {}
    for entry in LOG_ENTRIES:
        ip_counts[entry.ip_address] = ip_counts.get(entry.ip_address, 0) + 1
    top_ips_data = [{"ip": ip, "count": count} for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]]

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "normal_traffic": normal_traffic,
        "blocked_requests": blocked_requests,
        "attack_attempts": attack_attempts,
        "recent_logs": recent_logs,
        "status_data": sorted(status_data, key=lambda x: x["status"]),
        "hourly_data": sorted(hourly_data, key=lambda x: x["hour"]),
        "top_ips": top_ips_data,
        "now": datetime.now()
    })

@app.get("/logs/{log_type}", response_class=HTMLResponse)
async def logs_page(
    request: Request,
    log_type: str,
    page: int = 1,
    rule_filter: Optional[str] = None,
    severity_filter: Optional[str] = None
):
    global LOG_ENTRIES
    LOG_ENTRIES = parse_modsec_log(LOG_FILE_PATH)  # Re-parse logs on each logs page request

    entries = filter_logs(log_type, rule_filter, severity_filter)
    total_entries = len(entries)
    total_pages = max(1, (total_entries + PER_PAGE - 1) // PER_PAGE)
    page = max(1, min(page, total_pages))

    paginated = entries[(page - 1) * PER_PAGE: page * PER_PAGE]

    title_map = {
        "normal": "Normal Traffic",
        "blocked": "Blocked Requests",
        "attack": "Attack Attempts",
        "total": "Total Requests"
    }
    title = title_map.get(log_type, "Unknown Log Type")

    return templates.TemplateResponse("logs.html", {
        "request": request,
        "entries": paginated,
        "page": page,
        "has_next": page < total_pages,
        "has_prev": page > 1,
        "log_type": log_type,
        "title": title,
        "total_pages": total_pages,
        "rule_filter": rule_filter,
        "severity_filter": severity_filter
    })

@app.get("/export/csv")
async def export_csv(
    log_type: str = Query("total"),
    rule_filter: Optional[str] = None,
    severity_filter: Optional[str] = None
):
    entries = filter_logs(log_type, rule_filter, severity_filter)

    def generate():
        buffer = StringIO()
        writer = csv.writer(buffer)
        writer.writerow([
            "Timestamp", "IP", "Port", "Method", "Path", "Status",
            "Rule ID", "Rule Message", "Rule Severity", "Rule Data"
        ])
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)

        for entry in entries:
            if entry.rule_messages:
                for rule in entry.rule_messages:
                    writer.writerow([
                        entry.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                        entry.ip_address,
                        entry.port,
                        entry.method,
                        entry.path,
                        entry.status,
                        rule.rule_id,
                        rule.rule_msg,
                        rule.rule_severity or "",
                        rule.rule_data or ""
                    ])
            else:
                writer.writerow([
                    entry.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    entry.ip_address,
                    entry.port,
                    entry.method,
                    entry.path,
                    entry.status,
                    "", "", "", ""
                ])
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)

    filename = build_export_filename(log_type, rule_filter, severity_filter)
    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}.csv"}
    )

@app.get("/export/pdf")
async def export_pdf(
    request: Request,
    log_type: str = Query("total"),
    rule_filter: Optional[str] = None,
    severity_filter: Optional[str] = None
):
    entries = filter_logs(log_type, rule_filter, severity_filter)
    total_requests = len(LOG_ENTRIES)
    blocked_requests = len([e for e in LOG_ENTRIES if e.status in (406, 414)])
    attack_attempts = len([e for e in LOG_ENTRIES if e.status == 403])

    title_map = {
        "total": "Total Requests",
        "normal": "Normal Traffic",
        "blocked": "Blocked Requests",
        "attack": "Attack Attempts"
    }
    title = title_map.get(log_type, "Unknown Log Type")

    chart_data = calculate_chart_data(entries)

    temp_dir = tempfile.mkdtemp()
    try:
        status_chart_path = os.path.join(temp_dir, "status_chart.png")
        hourly_chart_path = os.path.join(temp_dir, "hourly_chart.png")
        donut_chart_path = os.path.join(temp_dir, "donut_chart.png")

        generate_chart_image(chart_data["status_data"], "bar", status_chart_path, "Status Code Distribution")
        generate_chart_image(chart_data["hourly_data"], "line", hourly_chart_path, "Hourly Distribution")

        metrics_data = {
            "normal_traffic": len([e for e in entries if 200 <= e.status <= 399 or e.status in (401, 404)]),
            "blocked_requests": len([e for e in entries if e.status in (406, 414)]),
            "attack_attempts": len([e for e in entries if e.status == 403])
        }
        generate_donut_chart_image(metrics_data, donut_chart_path)

        def image_to_base64(path):
            with open(path, "rb") as f:
                return base64.b64encode(f.read()).decode("utf-8")

        status_chart_b64 = image_to_base64(status_chart_path)
        hourly_chart_b64 = image_to_base64(hourly_chart_path)
        donut_chart_b64 = image_to_base64(donut_chart_path)

        # Prepare entries with formatted data
        formatted_entries = []
        for entry in entries:
            rule_text = ""
            if entry.rule_messages:
                rule_text = "<br>".join(
                    f"ID: {rule.rule_id}, Severity: {rule.rule_severity}, Message: {rule.rule_msg}"
                    for rule in entry.rule_messages
                )
            
            formatted_entries.append({
                "timestamp": entry.timestamp.strftime('%Y-%m-%d %H:%M:%S') if entry.timestamp else "N/A",
                "ip_address": entry.ip_address,
                "port": entry.port,
                "method": entry.method,
                "path": entry.path,
                "status": entry.status,
                "rule_text": rule_text
            })

        html_content = templates.get_template("logs_pdf.html").render({
            "request": request,
            "entries": formatted_entries,
            "title": title,
            "total_requests": total_requests,
            "blocked_requests": blocked_requests,
            "attack_attempts": attack_attempts,
            "status_chart": status_chart_b64,
            "hourly_chart": hourly_chart_b64,
            "donut_chart": donut_chart_b64,
            "now": datetime.now()
        })

        pdf = HTML(string=html_content).write_pdf()
        filename = build_export_filename(log_type, rule_filter, severity_filter) + ".pdf"
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.post("/reset-logs")
async def reset_logs():
    global LOG_ENTRIES
    try:
        with open(LOG_FILE_PATH, "w") as f:
            f.truncate(0)
        LOG_ENTRIES = []
        return RedirectResponse(url="/", status_code=303)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error resetting logs: {str(e)}")

def filter_logs(log_type: str, rule_filter: Optional[str], severity_filter: Optional[str]) -> List[LogEntry]:
    entries = LOG_ENTRIES

    if log_type == "normal":
        entries = [e for e in entries if 200 <= e.status <= 399 or e.status in (401, 404)]
    elif log_type == "blocked":
        entries = [e for e in entries if e.status in (406, 414)]
    elif log_type == "attack":
        entries = [e for e in entries if e.status == 403]
    elif log_type != "total":
        raise HTTPException(status_code=400, detail="Invalid log type")

    if rule_filter:
        entries = [
            e for e in entries if any(
                rule_filter.lower() in (msg.rule_msg or "").lower() or
                rule_filter.lower() in (msg.rule_data or "").lower()
                for msg in e.rule_messages
            )
        ]

    if severity_filter:
        entries = [
            e for e in entries if any(
                severity_filter.lower() in (msg.rule_severity or "").lower()
                for msg in e.rule_messages
            )
        ]

    return sorted(entries, key=lambda x: x.timestamp, reverse=True)

def build_export_filename(log_type, rule_filter, severity_filter):
    filename = f"modsec_logs_{log_type}"
    if rule_filter:
        filename += f"_{rule_filter[:20].replace(' ', '_')}"
    if severity_filter:
        filename += f"_{severity_filter.lower()}"
    filename += f"_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    return filename

def calculate_chart_data(log_entries):
    status_counts = defaultdict(int)
    hourly_counts = defaultdict(int)
    ip_counts = defaultdict(int)

    for entry in log_entries:
        if entry.status:
            status_counts[entry.status] += 1

        if entry.timestamp:
            hourly_counts[entry.timestamp.hour] += 1

        ip_counts[entry.ip_address] += 1

    status_data = sorted([{"status": str(k), "count": v} for k, v in status_counts.items()], key=lambda x: x["status"])
    hourly_data = sorted([{"hour": k, "count": v} for k, v in hourly_counts.items()], key=lambda x: x["hour"])
    top_ips = sorted([{"ip": k, "count": v} for k, v in ip_counts.items()], key=lambda x: -x["count"])[:10]

    return {
        "status_data": status_data,
        "hourly_data": hourly_data,
        "top_ips": top_ips
    }

def generate_chart_image(data, chart_type, output_path, title):
    plt.figure(figsize=(8, 4))

    if chart_type == "bar":
        labels = [str(item["status"]) for item in data]
        values = [item["count"] for item in data]
        colors = [get_matplotlib_color(int(item["status"])) for item in data]

        plt.bar(labels, values, color=colors)
        plt.xlabel('Status Code')
    elif chart_type == "line":
        hours = [item["hour"] for item in data]
        counts = [item["count"] for item in data]

        plt.plot(hours, counts, marker='o', color='#0d6efd', linewidth=2)
        plt.fill_between(hours, counts, color='#0d6efd', alpha=0.1)
        plt.xlabel('Hour of Day')

    plt.ylabel('Number of Requests')
    plt.title(title)
    plt.grid(True, linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()

def generate_donut_chart_image(metrics_data, output_path):
    labels = ['Normal Traffic', 'Rule Violations', 'Attack Attempts']
    sizes = [metrics_data["normal_traffic"],
             metrics_data["blocked_requests"],
             metrics_data["attack_attempts"]]
    colors = ['#198754', '#ffc107', '#dc3545']

    plt.figure(figsize=(6, 6))
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
            startangle=90, wedgeprops=dict(width=0.4))
    plt.title('Request Type Distribution')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()

def get_matplotlib_color(status_code):
    if status_code == 403:
        return '#dc3545'
    if status_code in (406, 414):
        return '#ffc107'
    if 200 <= status_code < 400:
        return '#198754'
    if status_code in (401, 404):
        return '#0d6efd'
    return '#6c757d'
