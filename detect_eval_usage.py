import os
import re

JS_EXTENSION = '.js'

# Regex pattern to match eval()
EVAL_PATTERN = re.compile(r'\beval\s*\(', re.IGNORECASE)


def scan_file(file_path):
    eval_usages = []

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        if EVAL_PATTERN.search(line):
            eval_usages.append((i + 1, line.strip()))

    return {
        'file': file_path,
        'eval_calls': eval_usages
    }


def scan_directory(directory):
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(JS_EXTENSION):
                file_path = os.path.join(root, file)
                result = scan_file(file_path)
                if result['eval_calls']:
                    results.append(result)
    return results


def print_report(results):
    for result in results:
        print(f"\n📁 File: {result['file']}")
        print("🚨 Dangerous eval() usage detected:")
        for line_num, line in result['eval_calls']:
            print(f"  Line {line_num}: {line}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Scan JavaScript files for eval() usage.")
    parser.add_argument("directory", help="Directory to scan")
    args = parser.parse_args()

    results = scan_directory(args.directory)
    if results:
        print_report(results)
    else:
        print("✅ No eval() usage found.")
    