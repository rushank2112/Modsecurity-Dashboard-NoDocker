import os
import re
import glob
import csv
import base64
import shutil
import tempfile
from collections import defaultdict
from datetime import datetime
from io import StringIO
from typing import Optional, List
import subprocess
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import matplotlib.pyplot as plt
from weasyprint import HTML
from typing import Dict
from pathlib import Path
from parser import extract_rule_descriptions_from_log

from models import LogEntry, RuleMessage, ModSecRule, RuleAction
from parser import parse_modsec_log
from pydantic import BaseModel
import json

from modsec_rule_toggle import disable_rule, enable_rule, log, load_state, save_state


app = FastAPI()
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

PER_PAGE = 20
LOG_FILE_PATH = "/var/log/apache2/modsec_audit.log"
LOG_ENTRIES: List[LogEntry] = []
RULE_FILES_GLOB = "/usr/share/modsecurity-crs/rules/*.conf"
RULE_STATE_FILE = "/var/lib/modsecurity/rule_states.json"
RULE_DIR = "/usr/share/modsecurity-crs/rules"

# In-memory rule change queue
PENDING_RULE_UPDATES: Dict[str, RuleAction] = {}

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


# === Models ===
class UpdateActionRequest(BaseModel):
    action: RuleAction

# === API Routes ===
@app.get("/api/rules", response_model=List[ModSecRule])
async def get_all_rules():
    log_msg_map = extract_rule_descriptions_from_log(LOG_FILE_PATH)
    return load_rules_from_files(log_msg_map)

@app.get("/api/rules/{rule_id}", response_model=ModSecRule)
async def get_rule(rule_id: str):
    return find_rule_by_id(rule_id)


@app.post("/api/rules/{rule_id}/action")
async def update_rule_action(rule_id: str, req: UpdateActionRequest):
    try:
        print(f"🔧 Received POST request to update rule {rule_id} with action: {req.action}")

        update_rule_config(rule_id, req.action)

        # Apply the config changes immediately
        result = apply_config_changes()

        return {
            "message": f"✅ Rule {rule_id} successfully updated to '{req.action}'",
            "apply_result": result
        }

    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"❌ Rule {rule_id} not found: {e}"
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"⚠️ Invalid action for rule {rule_id}: {e}"
        )

    except HTTPException as e:
        # If apply_config_changes raises HTTPException, propagate it
        raise e

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"🚨 Unexpected error while updating rule {rule_id}: {str(e)}"
        )





@app.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    return templates.TemplateResponse("rules_management.html", {"request": request})

# === Rule Management Logic ===

def load_rules_from_files(log_msg_map: Dict[str, str] = None) -> List[ModSecRule]:
    """
    Load ModSecurity rules from files, handling both traditional and shorthand formats.
    
    Args:
        log_msg_map: Optional dictionary mapping rule IDs to descriptions
        
    Returns:
        List of ModSecRule objects representing all rules (both active and disabled)
    """
    rules = []
    rule_files = glob.glob(RULE_FILES_GLOB)
    print(f"DEBUG: Found rule files: {rule_files}")

    found_rule_ids = set()

    for file_path in rule_files:
        print(f"\nDEBUG: Processing file: {file_path}")
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Normalize line endings and split into lines
        lines = content.replace('\r\n', '\n').split('\n')
        
        active_rules_text = []
        disabled_rules_in_file = []
        current_rule_lines = []
        collecting_rule = False
        is_disabled_rule = False
        is_shorthand_format = False

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip empty lines
            if not stripped:
                if current_rule_lines:
                    current_rule_lines.append(line)  # Preserve empty lines within rule blocks
                continue

            # Handle both traditional and shorthand rule formats
            if not collecting_rule:
                # Check for traditional SecRule format (commented or active)
                if re.match(r'^\s*#.*SecRule', line):
                    print(f"DEBUG: Line {line_num}: Found commented SecRule")
                    is_disabled_rule = True
                    current_rule_lines = [line]
                    collecting_rule = True
                elif re.match(r'^\s*SecRule', line):
                    print(f"DEBUG: Line {line_num}: Found active SecRule")
                    is_disabled_rule = False
                    current_rule_lines = [line]
                    collecting_rule = True
                # Check for shorthand rule format (starts with id:)
                elif re.match(r'^\s*#?\s*id:\d+', line):
                    print(f"DEBUG: Line {line_num}: Found shorthand rule format")
                    is_shorthand_format = True
                    is_disabled_rule = line.lstrip().startswith('#')
                    current_rule_lines = [line]
                    collecting_rule = True
                continue

            # If we're collecting a rule
            if collecting_rule:
                current_rule_lines.append(line)
                
                # For traditional SecRule format, check for line continuation
                if not is_shorthand_format:
                    if not line.rstrip().endswith('\\'):
                        collecting_rule = False
                # For shorthand format, check for rule end (no comma at end)
                else:
                    if not line.rstrip().endswith(','):
                        collecting_rule = False

                # When we finish collecting a complete rule
                if not collecting_rule:
                    rule_block = '\n'.join(current_rule_lines)
                    rule_id_match = re.search(r'id:(\d+)', rule_block)
                    
                    if rule_id_match:
                        rule_id = rule_id_match.group(1)
                        if is_disabled_rule:
                            print(f"DEBUG: Found DISABLED rule {rule_id} in file {file_path}")
                            disabled_rules_in_file.append((rule_id, rule_block, file_path))
                        else:
                            print(f"DEBUG: Found ACTIVE rule {rule_id} in file {file_path}")
                            active_rules_text.append(rule_block)
                    else:
                        print(f"DEBUG: No ID found in rule block. Content:\n{rule_block[:200]}...")
                    
                    # Reset state for next rule
                    current_rule_lines = []
                    is_disabled_rule = False
                    is_shorthand_format = False

        # Process active rules
        for rule_text in active_rules_text:
            rule_id_match = re.search(r'id:(\d+)', rule_text)
            if not rule_id_match:
                print(f"DEBUG: Active rule with no ID found. Content:\n{rule_text[:200]}...")
                continue

            rule_id = rule_id_match.group(1)
            if rule_id in found_rule_ids:
                print(f"DEBUG: Skipping duplicate active rule {rule_id}")
                continue

            found_rule_ids.add(rule_id)

            # Extract description from msg or use rule text
            msg_match = re.search(r"msg:'([^']+)'", rule_text) or re.search(r'msg:"([^"]+)"', rule_text)
            description = log_msg_map.get(rule_id) if log_msg_map else None
            description = description or msg_match.group(1) if msg_match else rule_text
            
            filename = Path(file_path).stem
            category = filename.split('-')[1] if '-' in filename else "General"
            
            # Extract severity (supporting both single and double quotes)
            severity_match = re.search(r"severity:\s*['\"](?P<severity>\w+)['\"]", rule_text, re.IGNORECASE)
            severity = severity_match.group("severity").upper() if severity_match else None

            rules.append(ModSecRule(
                rule_id=rule_id,
                file_name=filename,
                description=description,
                default_action=RuleAction.BLOCK,
                current_action=RuleAction.BLOCK,
                severity=severity,
                category=category
            ))

        # Process disabled rules
        for rule_id, rule_text, file_path in disabled_rules_in_file:
            if rule_id in found_rule_ids:
                print(f"DEBUG: Skipping disabled rule {rule_id} because already loaded as active")
                continue

            msg_match = re.search(r"msg:'([^']+)'", rule_text) or re.search(r'msg:"([^"]+)"', rule_text)
            description = msg_match.group(1) if msg_match else rule_text
            filename = Path(file_path).stem
            category = filename.split('-')[1] if '-' in filename else "General"
            
            severity_match = re.search(r"severity:\s*['\"](?P<severity>\w+)['\"]", rule_text, re.IGNORECASE)
            severity = severity_match.group("severity").upper() if severity_match else None

            rules.append(ModSecRule(
                rule_id=rule_id,
                file_name=filename,
                description=description,
                default_action=RuleAction.BLOCK,
                current_action=RuleAction.DISABLED,
                severity=severity,
                category=category
            ))
            found_rule_ids.add(rule_id)

    print(f"\nDEBUG: Rule loading complete. Total rules: {len(rules)} "
          f"(Active: {len([r for r in rules if r.current_action != RuleAction.DISABLED])}, "
          f"Disabled: {len([r for r in rules if r.current_action == RuleAction.DISABLED])})")
    return rules



def parse_single_rule_block(content: str, file_path: str, log_msg_map: Dict[str, str], is_commented: bool) -> List[ModSecRule]:
    matches = re.finditer(
        r'SecRule\s+(.*?)\s+(.*?)\s+"(id:(\d+)[^"]*phase:\d+[^"]*)"',
        content,
        re.DOTALL
    )

    extracted_rules = []
    for match in matches:
        rule_id = match.group(4)
        full_rule_text = match.group(3)

        # Determine description
        if log_msg_map and rule_id in log_msg_map:
            description = log_msg_map[rule_id]
        else:
            msg_match = re.search(r"msg:'([^']+)'", full_rule_text)
            description = msg_match.group(1) if msg_match else full_rule_text

        filename = Path(file_path).stem
        category = filename.split('-')[1] if '-' in filename else "General"
        severity_match = re.search(r"severity:\s*'?(?P<severity>\w+)'?", full_rule_text, re.IGNORECASE)
        severity = severity_match.group("severity").upper() if severity_match else None

        extracted_rules.append(ModSecRule(
            rule_id=rule_id,
            file_name=filename,
            description=description,
            default_action=RuleAction.BLOCK,
            current_action="disabled" if is_commented else get_current_rule_action(rule_id),
            severity=severity,
            category=category
        ))

        print(f"DEBUG: Rule {rule_id} from {file_path} is {'DISABLED' if is_commented else 'ACTIVE'}")

    return extracted_rules





def find_rule_by_id(rule_id: str) -> ModSecRule:
    for rule in load_rules_from_files():
        if rule.rule_id == rule_id:
            return rule
    raise HTTPException(status_code=404, detail="Rule not found")

def get_current_rule_action(rule_id: str) -> RuleAction:
    return PENDING_RULE_UPDATES.get(rule_id, RuleAction.BLOCK)

def update_rule_config(rule_id: str, action: RuleAction):
    PENDING_RULE_UPDATES[rule_id] = action



def init_rule_states():
    os.makedirs(os.path.dirname(RULE_STATE_FILE), exist_ok=True)
    if not os.path.exists(RULE_STATE_FILE):
        with open(RULE_STATE_FILE, 'w') as f:
            json.dump({"disabled_rules": {}}, f)

def find_rule_file(rule_id):
    rule_file = os.popen(f'grep -l "id:{rule_id}" {RULE_DIR}/*').read().strip()
    if not rule_file:
        raise FileNotFoundError(f"Rule {rule_id} not found")
    return rule_file

def comment_out_rule(rule_id, rule_file):
    os.system(f'sed -i "s/\\(.*id:{rule_id}.*\\)/# \\1/" "{rule_file}"')

def uncomment_rule(rule_id, rule_file):
    os.system(f'sed -i "s/^# \\(.*id:{rule_id}.*\\)/\\1/" "{rule_file}"')

def is_rule_disabled(rule_id, rule_file):
    result = os.popen(f'grep "^#.*id:{rule_id}" "{rule_file}"').read()
    return bool(result.strip())

def is_rule_enabled(rule_id, rule_file):
    result = os.popen(f'grep -v "^#" "{rule_file}" | grep "id:{rule_id}"').read()
    return bool(result.strip())



def apply_config_changes():
    print("apply_config_changes called")
    success_updates = []
    failed_updates = []

    for raw_rule_id, raw_action in PENDING_RULE_UPDATES.items():
        rule_id = str(raw_rule_id).strip()
        action = raw_action.strip().lower()

        if action not in ("block","monitor", "disabled"):
            print(f"⚠️ Invalid action '{action}' for rule {rule_id}")
            failed_updates.append(rule_id)
            continue

        try:
            if action == "disabled":
                print(f"Disabling rule with Rule ID : {rule_id}")
                disable_rule(rule_id)
            elif action == "block":
                enable_rule(rule_id)

            print(f"✅ {action.title()} rule {rule_id} successfully")
            success_updates.append(rule_id)

        except Exception as e:
            print(f"❌ Failed to {action} rule {rule_id}: {e}")
            failed_updates.append(rule_id)

    PENDING_RULE_UPDATES.clear()

    if failed_updates:
        raise HTTPException(
            status_code=207,
            detail={
                "message": "Some rule changes failed",
                "updated": success_updates,
                "failed": failed_updates
            }
        )

    return {"status": "success", "updated": success_updates}




def load_disabled_rules_state():
    try:
        with open(RULE_STATE_FILE, "r") as f:
            state = json.load(f)
        return state.get("disabled_rules", {})
    except FileNotFoundError:
        return {}

def load_rules_with_disabled_state(log_msg_map=None):
    active_rules = load_rules_from_files(log_msg_map)
    disabled_rules_state = load_disabled_rules_state()

    # Build ModSecRule list from disabled_rules_state
    disabled_rules = []
    for rule_id, data in disabled_rules_state.items():
        if isinstance(data, dict):
            disabled_rules.append(ModSecRule(
                rule_id=rule_id,
                file_name=data.get("file", "unknown"),
                description=data.get("description", "Disabled by user"),
                default_action=RuleAction.BLOCK,
                current_action=RuleAction.DISABLED,
                severity=data.get("severity"),
                category=data.get("category", "Unknown"),
            ))
        else:
            # legacy fallback: just filename string
            disabled_rules.append(ModSecRule(
                rule_id=rule_id,
                file_name=data,
                description="Disabled by user",
                default_action=RuleAction.BLOCK,
                current_action=RuleAction.DISABLED,
                severity=None,
                category="Unknown",
            ))

    return active_rules + disabled_rules

#endpoint to handle saving custom rules
@app.post("/rules/custom")
async def save_custom_rule(rule_data: dict):
    custom_rules_path = os.path.join(RULE_DIR, "custom_rules4.conf")
    
    try:
        # Ensure the file exists and starts with a header if newly created
        if not os.path.exists(custom_rules_path):
            with open(custom_rules_path, 'w') as f:
                f.write("# Custom ModSecurity Rules\n\n")
            print(f"[INFO] Created file: {custom_rules_path}")

        # Append the custom rule
        with open(custom_rules_path, 'a') as f:
            f.write(f"\n{rule_data['rule_text']}\n")
        print("[INFO] Appended rule to custom_rules4.conf")

        # Reapply internal config if needed
        apply_config_changes()
        print("[INFO] Applied internal config changes")

        # Gracefully reload Apache to apply changes
        result = subprocess.run(["apachectl", "graceful"], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[ERROR] Apache reload failed: {result.stderr.strip()}")
            raise Exception(f"Apache reload failed: {result.stderr.strip()}")
        else:
            print("[INFO] Apache reloaded successfully")

        return {"status": "success", "message": "Custom rule added and Apache reloaded"}

    except Exception as e:
        print(f"[ERROR] Error saving custom rule: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error saving custom rule: {str(e)}"
        )


