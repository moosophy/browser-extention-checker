import os
import sys
import re
from collections import defaultdict
from patterns_and_keywords import *

found_fingerprint = set()

# Mapping of permission keywords to flag names
PERMISSION_MAPPING = {
    "fileSystemProvider": "fileSystemProvider_use",
    "gcm": "gcm_use",
    "cookies": "cookies_use",
    "clipboardRead": "clipboard_use",
    "contentSettings": "settings_use",
    "debugger": "debugger_use",
    "declarativeNetRequest": "declarativeNetRequest_use",
    "declarativeNetRequestFeedback": "declarativeNetRequestFeedback_use",
    "desktopCapture": "desktopCapture_use",
    "downloads": "downloads_use",
    "geolocation": "geolocation_use",
    "history": "history_use",
    "identity": "identity_use",
    "management": "management_use",
    "notifications": "notifications_use",
    "privacy": "privacy_use",
    "processes": "processes_use",
    "proxy": "proxy_use",
    "sessions": "sessions_use",
    "tabCapture": "tabCapture_use",
    "topSites": "topSites_use",
    "tabs": "tabs_use",
    "webAuthenticationProxy": "webAuthenticationProxy_use",
    "webNavigation": "webNavigation_use",
}

# Initialize flags using defaultdict for cleaner code
perm_flags = defaultdict(bool)
other_flags = defaultdict(bool)


def scan_folder(directory):
    """Recursively scan directory for .js and .json files."""
    valid_extensions = ('.js', '.json')
    
    for root, dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith(valid_extensions):
                check_file(root, filename)



def check_file(path, filename):
    """Check a single file for suspicious patterns and permissions."""
    file_path = os.path.join(path, filename)
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (IOError, OSError) as e:
        print(f"Warning: Could not read {file_path}: {e}")
        return
    
    # Check permissions in manifest.json
    if filename == "manifest.json":
        _check_permissions(content)
    
    # Check for suspicious file access patterns
    _check_file_access(content)
    
    # Check for fingerprinting patterns
    _check_fingerprinting(content)
    
    # Check for eval usage
    _check_eval_usage(content)
    
    # Check for suspicious listeners
    _check_listeners(content)


def _check_permissions(content):
    """Check manifest.json content for suspicious permissions."""
    for permission_keyword, flag_name in PERMISSION_MAPPING.items():
        if permission_keyword in content:
            perm_flags[flag_name] = True


def _check_file_access(content):
    """Check for file access patterns."""
    if any(keyword in content for keyword in file_access_keywords):
        perm_flags["file_reading"] = True


def _check_fingerprinting(content):
    """Check for fingerprinting patterns."""
    for pattern in fingerprint_patterns:
        if re.search(pattern, content):
            found_fingerprint.add(pattern)


def _check_eval_usage(content):
    """Check for eval usage patterns."""
    if any(re.search(pattern, content) for pattern in eval_patterns):
        other_flags["eval_use"] = True


def _check_listeners(content):
    """Check for suspicious event listeners."""
    if any(re.search(pattern, content) for pattern in listener_patterns):
        other_flags["sus_listener"] = True




def evaluate_malicious():
    """Evaluate the overall maliciousness based on collected flags."""
    # Count suspicious permissions
    num_shady_permissions = sum(perm_flags.values())
    if num_shady_permissions > 5:
        other_flags["too_many_permissions"] = True
    
    # Add fingerprinting permissions to found_fingerprint
    for permission in fingerprint_permissions:
        if perm_flags[permission]:
            found_fingerprint.add(permission)
    
    # Categorize fingerprinting risk
    fingerprint_count = len(found_fingerprint)
    if fingerprint_count > 8:
        other_flags["fingerprint_high"] = True
    elif fingerprint_count > 5:
        other_flags["fingerprint_medium"] = True
    elif fingerprint_count > 2:
        other_flags["fingerprint_low"] = True
        


def report_malicious():
    """Report all detected malicious patterns and permissions."""
    
    # Define messages for different flag types
    flag_messages = {
        "fingerprint_low": (
            f"‣ This extension collects some device or browser characteristics "
            f"that could be used for tracking.\n\tDetails collected:\n\t{found_fingerprint}"
        ),
        "fingerprint_medium": (
            f"‣ This extension collects a lot of browser and device details. "
            f"This data can be used for profiling.\n\tDetails collected:\n\t{found_fingerprint}"
        ),
        "fingerprint_high": (
            f"‣ This extension collects an extensive amount of fingerprinting data. "
            f"This extension might be profiling you or selling your data.\n\tDetails collected:\n\t{found_fingerprint}"
        ),
        "too_many_permissions": (
            "‣ This extension uses too many suspicious permissions. "
            "Unless it is a complex extension, this is highly suspicious."
        ),
        "eval_use": "‣ This extension uses eval(). That is highly suspicious.",
        "sus_listener": (
            "‣ This extension registers event listeners for sensitive browser actions "
            "like keyboard, clipboard, or tab activity."
        ),
    }

    perm_messages = {
        "gcm_use": (
            "‣ This extension can receive remote commands from an external server using "
            "Google's push messaging system (GCM). If the extension is not clearly "
            "advertised to provide real-time updates or messages, this is highly suspicious."
        ),
        "fileSystemProvider_use": "‣ This extension deals with remote files. Use it cautiously.",
        "file_reading": "‣ This extension can read submitted files! Avoid exposing sensitive data.",
        "clipboard_use": (
            "‣ This extension can read or modify clipboard content. If unnecessary, "
            "it could be used to steal copied information."
        ),
        "settings_use": (
            "‣ This extension modifies browser content settings. This could weaken "
            "security or allow unwanted behavior."
        ),
        "debugger_use": (
            "‣ This extension uses the debugger API, which allows full DevTools access "
            "to any tab. This is extremely dangerous unless it's a trusted developer tool."
        ),
        "declarativeNetRequest_use": (
            "‣ This extension intercepts or redirects browser traffic using static rules. "
            "If it modifies traffic from trusted sites, it may be a phishing attempt."
        ),
        "desktopCapture_use": (
            "‣ This extension can record your screen or window. If it's not a known "
            "screen-sharing tool, this is a privacy risk."
        ),
        "downloads_use": (
            "‣ This extension can download and automatically open files. This can be used "
            "to download viruses unless it is from a trusted source."
        ),
        "management_use": (
            "‣ This extension can list, disable, or remove other extensions. "
            "This is very powerful and should be treated with suspicion."
        ),
        "notifications_use": (
            "‣ This extension can create desktop notifications. If used for phishing "
            "or scam alerts, this could be dangerous."
        ),
        "privacy_use": (
            "‣ This extension can change your browser's privacy settings. If misused, "
            "it can reduce your protection against tracking and data leaks."
        ),
        "proxy_use": (
            "‣ This extension can change your proxy settings, potentially rerouting "
            "your internet traffic through malicious servers. Treat this with extreme "
            "caution unless it's a trusted VPN."
        ),
        "sessions_use": (
            "‣ This extension can access recently closed tabs and browsing sessions "
            "across your signed-in devices. Combined with other permissions, this can "
            "be used for detailed tracking."
        ),
        "tabCapture_use": (
            "‣ This extension can record audio or video from a browser tab. "
            "If it's not clearly a screen recording tool, this poses a major privacy risk."
        ),
        "tabs_use": (
            "‣ This extension can read and manipulate your browser tabs. "
            "This can be used for surveillance or phishing."
        ),
        "webAuthenticationProxy_use": (
            "‣ This extension can intercept login credentials via authentication proxying. "
            "This is extremely dangerous outside enterprise environments."
        ),
        "webNavigation_use": (
            "‣ This extension monitors your browsing activity, including redirects "
            "and page loads. Often used for behavior tracking."
        )
    }

    # Print behavioral flags
    _print_active_flags(other_flags, flag_messages)
    
    print("\nPERMISSIONS")
    
    # Print permission flags
    _print_active_flags(perm_flags, perm_messages)


def _print_active_flags(flags_dict, messages_dict):
    """Helper function to print active flags with their messages."""
    for flag_name, is_active in flags_dict.items():
        if is_active and flag_name in messages_dict:
            print(f"\n{messages_dict[flag_name]}")
        



def main():
    """Main function to run the extension checker."""
    if len(sys.argv) != 2:
        print("Usage: python check_extension.py <extension_directory>")
        sys.exit(1)
    
    extension_path = sys.argv[1]
    if not os.path.isdir(extension_path):
        print(f"Error: '{extension_path}' is not a valid directory")
        sys.exit(1)
    
    print("\nParsing files...")
    scan_folder(extension_path)
    print("Parsing finished.\n")

    evaluate_malicious()

    print("-" * 50 + "\n")
    print("RESULTS:")
    report_malicious()
    print("\n" + "-" * 50)




if __name__ == "__main__":
    main()
