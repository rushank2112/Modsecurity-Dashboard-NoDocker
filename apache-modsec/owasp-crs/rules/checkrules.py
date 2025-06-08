from collections import defaultdict
import glob, re

ids = defaultdict(list)
for filename in glob.glob("*.conf"):
    with open(filename) as f:
        for lineno, line in enumerate(f, 1):
            match = re.search(r'id:(\d+)', line)
            if match:
                rule_id = match.group(1)
                ids[rule_id].append((filename, lineno))

for rule_id, locations in ids.items():
    if len(locations) > 1:
        print(f"Duplicate ID {rule_id} found in:")
        for file, line in locations:
            print(f"  - {file}:{line}")
