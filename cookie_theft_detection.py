import os
import re

JS_EXTENSION = '.js'

# Patterns to detect cookie access and suspicious exfiltration
COOKIE_ACCESS_PATTERNS = [
    re.compile(r'document\.cookie', re.IGNORECASE),
    re.compile(r'chrome\.cookies', re.IGNORECASE),
    re.compile(r'cookies\.get', re.IGNORECASE),
]

EXFILTRATION_PATTERNS = [
    re.compile(r'fetch\s*\(', re.IGNORECASE),
    re.compile(r'XMLHttpRequest', re.IGNORECASE),
    re.compile(r'navigator\.sendBeacon', re.IGNORECASE),
    re.compile(r'\.open\s*\(\s*[\'"]POST', re.IGNORECASE),
]

def scan_file(file_path):
    findings = {
        'file': file_path,
        'cookie_access': [],
        'possible_exfiltration': [],
    }

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        for pattern in COOKIE_ACCESS_PATTERNS:
            if pattern.search(line):
                findings['cookie_access'].append((i + 1, line.strip()))

        for pattern in EXFILTRATION_PATTERNS:
            if pattern.search(line):
                findings['possible_exfiltration'].append((i + 1, line.strip()))

    return findings


def scan_directory(directory):
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(JS_EXTENSION):
                path = os.path.join(root, file)
                result = scan_file(path)
                if result['cookie_access'] or result['possible_exfiltration']:
                    results.append(result)
    return results


def print_results(results):
    for result in results:
        print(f"\n📁 File: {result['file']}")
        if result['cookie_access']:
            print("🔐 Cookie access detected:")
            for line_num, line in result['cookie_access']:
                print(f"  Line {line_num}: {line}")
        if result['possible_exfiltration']:
            print("🚨 Possible data exfiltration attempts:")
            for line_num, line in result['possible_exfiltration']:
                print(f"  Line {line_num}: {line}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Detect cookie access and possible exfiltration in JavaScript files.")
    parser.add_argument("directory", help="Directory to scan")
    args = parser.parse_args()

    results = scan_directory(args.directory)
    print_results(results)
