import re
from datetime import datetime
from fastapi import FastAPI, Request, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, StreamingResponse, Response, RedirectResponse
from collections import namedtuple, defaultdict
import os
import csv
from io import StringIO
from weasyprint import HTML
from typing import Optional
import tempfile
import shutil
import base64
import matplotlib.pyplot as plt

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

        if status in (406, 414):
            blocked_requests += 1
        if status == 403:
            attack_attempts += 1

        logs.append(LogEntry(timestamp, ip, port, method, path, status))

    return logs, total_requests, blocked_requests, attack_attempts

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
    if status_code == 403: return '#dc3545'  # red
    if status_code in (406, 414): return '#ffc107'  # yellow
    if 200 <= status_code < 400: return '#198754'  # green
    if status_code in (401, 404): return '#0d6efd'  # blue
    return '#6c757d'  # gray

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    log_entries, total_requests, blocked_requests, attack_attempts = parse_modsec_log(LOG_FILE_PATH)
    normal_traffic = total_requests - blocked_requests - attack_attempts
    recent_logs = list(reversed(log_entries))[:50]
    
    chart_data = calculate_chart_data(log_entries)
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "normal_traffic": normal_traffic,
        "blocked_requests": blocked_requests,
        "attack_attempts": attack_attempts,
        "recent_logs": recent_logs,
        "status_data": chart_data["status_data"],
        "hourly_data": chart_data["hourly_data"],
        "top_ips": chart_data["top_ips"],
        "now": datetime.now()
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

    # Generate chart data
    chart_data = calculate_chart_data(filtered)
    
    # Create a temporary directory for chart images
    temp_dir = tempfile.mkdtemp()
    try:
        # Generate chart images
        status_chart_path = os.path.join(temp_dir, "status_chart.png")
        hourly_chart_path = os.path.join(temp_dir, "hourly_chart.png")
        donut_chart_path = os.path.join(temp_dir, "donut_chart.png")

        generate_chart_image(chart_data["status_data"], "bar", status_chart_path, "Status Code Distribution")
        generate_chart_image(chart_data["hourly_data"], "line", hourly_chart_path, "Hourly Distribution")
        
        # For donut chart, we need metrics data
        metrics_data = {
            "normal_traffic": len([e for e in filtered if e.status and ((200 <= e.status < 400) or e.status in (401, 404))]),
            "blocked_requests": len([e for e in filtered if e.status in (406, 414)]),
            "attack_attempts": len([e for e in filtered if e.status == 403])
        }
        generate_donut_chart_image(metrics_data, donut_chart_path)

        # Read the images as base64
        def image_to_base64(path):
            with open(path, "rb") as image_file:
                return base64.b64encode(image_file.read()).decode('utf-8')

        status_chart_b64 = image_to_base64(status_chart_path)
        hourly_chart_b64 = image_to_base64(hourly_chart_path)
        donut_chart_b64 = image_to_base64(donut_chart_path)

        html_content = templates.get_template("logs_pdf.html").render({
            "request": request,
            "entries": filtered,
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
        filename = f"modsec_report_{log_type}.pdf"
        return Response(content=pdf, media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename={filename}"
        })
    finally:
        # Clean up temporary files
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.post("/reset-logs")
def reset_logs():
    with open(LOG_FILE_PATH, "w") as f:
        f.truncate(0)
    return RedirectResponse(url="/", status_code=303)

def filter_logs(log_entries, log_type: str):
    if log_type == "normal":
        filtered = [e for e in log_entries if e.status and (
            (200 <= e.status < 400) or e.status in (401, 404)
        )]
    elif log_type == "blocked":
        filtered = [e for e in log_entries if e.status in (406, 414)]
    elif log_type == "attack":
        filtered = [e for e in log_entries if e.status == 403]
    elif log_type == "total":
        filtered = log_entries
    else:
        filtered = []
    return filtered