import os
import re

# Define patterns of interest
EVENT_LISTENER_PATTERN = re.compile(r'\.addEventListener\s*\(\s*[\'"](\w+)[\'"]\s*,', re.IGNORECASE)
SENSITIVE_FIELD_PATTERN = re.compile(r'document\.getElement(ById|sByClassName|sByTagName)?\s*\(\s*[\'"].*?(password|card|ssn|security).*?[\'"]\s*\)', re.IGNORECASE)
GLOBAL_TARGET_PATTERN = re.compile(r'(window|document)\.addEventListener', re.IGNORECASE)

SUSPICIOUS_EVENTS = {'keydown', 'keypress', 'input', 'keyup', 'change', 'mousemove', 'click', 'scroll', 'wheel'}
JS_EXTENSION = '.js'


def scan_js_file(file_path):
    suspicious_events = []
    sensitive_field_lines = []
    global_listener_lines = []
    total_event_listeners = 0

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        # Check for addEventListener calls
        event_match = EVENT_LISTENER_PATTERN.search(line)
        if event_match:
            total_event_listeners += 1
            event_type = event_match.group(1).lower()
            if event_type in SUSPICIOUS_EVENTS:
                suspicious_events.append((i + 1, event_type, line.strip()))

        # Check for sensitive field access
        if SENSITIVE_FIELD_PATTERN.search(line):
            sensitive_field_lines.append((i + 1, line.strip()))

        # Check for global scope event listeners
        if GLOBAL_TARGET_PATTERN.search(line):
            global_listener_lines.append((i + 1, line.strip()))

    return {
        'file': file_path,
        'total_event_listeners': total_event_listeners,
        'suspicious_events': suspicious_events,
        'sensitive_fields': sensitive_field_lines,
        'global_listeners': global_listener_lines
    }


def analyze_directory(directory):
    report = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(JS_EXTENSION):
                file_path = os.path.join(root, file)
                result = scan_js_file(file_path)
                if result['suspicious_events'] or result['sensitive_fields'] or result['global_listeners']:
                    report.append(result)
    return report


def print_report(report):
    for entry in report:
        print(f"\n--- Analysis of {entry['file']} ---")
        print(f"Total event listeners: {entry['total_event_listeners']}")
        if entry['global_listeners']:
            print("Global listeners detected:")
            for line_num, line in entry['global_listeners']:
                print(f"  Line {line_num}: {line}")
        if entry['sensitive_fields']:
            print("Sensitive field access detected:")
            for line_num, line in entry['sensitive_fields']:
                print(f"  Line {line_num}: {line}")
        if entry['suspicious_events']:
            print("Suspicious event listeners detected:")
            for line_num, event, line in entry['suspicious_events']:
                print(f"  Line {line_num}: event '{event}' → {line}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Detect suspicious JavaScript event listeners.")
    parser.add_argument("directory", help="Directory to scan")
    args = parser.parse_args()

    result = analyze_directory(args.directory)
    print_report(result)
