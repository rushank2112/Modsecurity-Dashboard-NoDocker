import os
import json
import re
import argparse
import sys
from datetime import datetime
import subprocess

RULE_DIR = "/usr/share/modsecurity-crs/rules"
RULE_STATE_FILE = "/etc/modsecurity/persistent/rule_state.json"

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")

def init_rule_state_file():
    if not os.path.exists(RULE_STATE_FILE):
        os.makedirs(os.path.dirname(RULE_STATE_FILE), exist_ok=True)
        with open(RULE_STATE_FILE, "w") as f:
            json.dump({"disabled_rules": {}}, f)
        log(f"Initialized rule state file at {RULE_STATE_FILE}")

def load_state():
    log(f"Loading rule state from {RULE_STATE_FILE}")
    with open(RULE_STATE_FILE) as f:
        return json.load(f)

def save_state(state):
    with open(RULE_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    log(f"Saved updated rule state to {RULE_STATE_FILE}")

def collect_rule_block(lines, start_index):
    block_lines = [lines[start_index]]
    i = start_index + 1
    while i < len(lines):
        block_lines.append(lines[i])
        if lines[i].strip().endswith('"'):
            break
        i += 1
    return block_lines, i

def rule_matches_id(block_lines, rule_id):
    rule_text = "".join(block_lines).replace(" ", "")
    return re.search(rf"id[:=]['\"]?{rule_id}['\"]?\b", rule_text)

def disable_rule(rule_id):
    rule_id = str(rule_id)
    log(f"Disabling rule {rule_id}")
    init_rule_state_file()
    state = load_state()
    restart_needed = False

    for filename in os.listdir(RULE_DIR):
        if not filename.endswith(".conf"):
            continue

        path = os.path.join(RULE_DIR, filename)
        with open(path, "r") as f:
            lines = f.readlines()

        new_lines = []
        i = 0
        modified = False

        while i < len(lines):
            line = lines[i]
            if re.search(r'\bSecRule\b', line):
                block_lines, end_index = collect_rule_block(lines, i)
                if rule_matches_id(block_lines, rule_id):
                    if not all(l.strip().startswith("#") for l in block_lines):
                        commented_block = ["# " + l if not l.strip().startswith("#") else l for l in block_lines]
                        new_lines.extend(commented_block)
                        modified = True
                        restart_needed = True

                        rule_text = "".join(block_lines)
                        state['disabled_rules'][rule_id] = {
                            "file": filename,
                            "rule_text": rule_text,
                            "disabled_at": datetime.now().isoformat()
                        }

                        i = end_index + 1
                        continue
                new_lines.extend(block_lines)
                i = end_index + 1
            else:
                new_lines.append(line)
                i += 1

        if modified:
            with open(path, "w") as f:
                f.writelines(new_lines)
            log(f"Disabled rule {rule_id} in {filename}")
            break  # Stop after first match

    if restart_needed:
        save_state(state)
        try:
            subprocess.run(['apachectl', 'graceful'], check=True)
            log("Apache gracefully restarted to apply changes")
        except subprocess.CalledProcessError as e:
            log(f"Error restarting Apache: {e}")
            raise
    else:
        log(f"Rule {rule_id} not found or already disabled")

def enable_rule(rule_id):
    rule_id = str(rule_id)
    log(f"Enabling rule {rule_id}")
    init_rule_state_file()
    state = load_state()
    restart_needed = False

    if rule_id not in state['disabled_rules']:
        log(f"Rule {rule_id} is not currently disabled")
        return False

    filename = state['disabled_rules'][rule_id]['file']
    path = os.path.join(RULE_DIR, filename)

    with open(path, "r") as f:
        lines = f.readlines()

    new_lines = []
    i = 0
    modified = False

    while i < len(lines):
        line = lines[i]
        if re.match(r'^\s*#\s*SecRule', line):
            block_lines, end_index = collect_rule_block(lines, i)
            if rule_matches_id(block_lines, rule_id):
                uncommented_block = [re.sub(r'^\s*#\s*', '', l) for l in block_lines]
                new_lines.extend(uncommented_block)
                modified = True
                restart_needed = True
                state['disabled_rules'].pop(rule_id, None)
                i = end_index + 1
                continue
            new_lines.extend(block_lines)
            i = end_index + 1
        else:
            new_lines.append(line)
            i += 1

    if modified:
        with open(path, "w") as f:
            f.writelines(new_lines)
        save_state(state)
        log(f"Enabled rule {rule_id} in {filename}")

        try:
            subprocess.run(['apachectl', 'graceful'], check=True)
            log("Apache gracefully restarted to apply changes")
        except subprocess.CalledProcessError as e:
            log(f"Error restarting Apache: {e}")
            raise
        return True
    else:
        log(f"Rule {rule_id} not found or already enabled")
        return False

def main():
    log("=== Script Started ===")
    parser = argparse.ArgumentParser(description="Enable or disable a ModSecurity rule by ID.")
    parser.add_argument("--rule-id", required=True, help="The ModSecurity rule ID to toggle")
    parser.add_argument("--action", required=True, choices=["block", "monitor", "disabled"], help="Action to perform")

    args = parser.parse_args()
    log(f"Arguments received: rule_id={args.rule_id}, action={args.action}")

    try:
        if args.action == "disabled":
            disable_rule(args.rule_id)
        elif args.action in ("block", "monitor"):
            enable_rule(args.rule_id)
        else:
            log(f"⚠️ Unknown action: {args.action}")
            sys.exit(1)
    except Exception as e:
        log(f"❌ Error: {e}")
        sys.exit(1)

    log("=== Script Finished ===")

if __name__ == "__main__":
    main()
