import os, sys
import re
from patterns_and_keywords import *

found_fingerprint = set()

# perm_flags for malicious activities
perm_flags = {
    "fileSystemProvider_use": False,
    "gcm_use": False,
    "cookies_use": False,
    "clipboard_use": False,
    "settings_use": False,
    "debugger_use": False,
    "declarativeNetRequest_use": False,
    "declarativeNetRequestFeedback_use": False, # track browsing behavior
    "desktopCapture_use": False,
    "downloads_use": False,
    "geolocation_use": False,
    "history_use": False,
    "identity_use": False,
    "management_use": False,
    "notifications_use": False,
    "privacy_use": False,
    "processes_use": False,
    "proxy_use": False,
    "sessions_use": False,
    "tabCapture_use": False,
    "topSites_use": False,
    "tabs_use": False,
    "webAuthenticationProxy_use": False,
    "webNavigation_use": False,
}
other_flags = {
    "fingerprint_low": False,
    "fingerprint_medium": False,
    "fingerprint_high": False,
    "file_reading": False,
    "eval_use": False,
    "too_many_permissions": False,
    "sus_listener": False
}


#Recursively parse a directory, to read the contents of all the files in that directory
# and all the files in it's subdirectory
def scanFolder(directory):
    for path, folders, files in os.walk(directory):
        for filename in files:
            if not filename.endswith(".js") and not filename.endswith(".json"):
                continue
            
            checkFile(path, filename)
        for folder_name in folders:
            scanFolder(os.path.join(path, folder_name))
        break



def checkFile(path, filename):
    file_path = os.path.join(path, filename)
    with open(file_path, errors="ignore") as f:
        content = f.read()
        #-------------------------- PERMISSIONS --------------------------------
        if filename == "manifest.json":
            if "fileSystemProvider" in content:
                perm_flags["fileSystemProvider_use"] = True
            if "gcm" in content: perm_flags["gcm_use"] = True
            if "cookies" in content: perm_flags["cookies_use"] = True
            
            #Now for permissions that chrome commonly warns about:
            if "clipboardRead" in content: perm_flags["clipboard_use"] = True
            if "contentSettings" in content: perm_flags["settings_use"] = True
            if "debugger" in content: perm_flags["debugger_use"] = True
            if "declarativeNetRequest" in content: perm_flags["declarativeNetRequest_use"] = True
            if "declarativeNetRequestFeedback" in content: 
                perm_flags["declarativeNetRequestFeedback_use"] = True

            if "desktopCapture" in content: perm_flags["desktopCapture_use"] = True
            if "downloads" in content: perm_flags["downloads_use"] = True
            if "geolocation" in content: perm_flags["geolocation_use"] = True
            if "history" in content: perm_flags["history_use"] = True
            if "identity" in content: perm_flags["identity_use"] = True
            if "management" in content: perm_flags["management_use"] = True
            if "notifications" in content: perm_flags["notifications_use"] = True
            if "privacy" in content: perm_flags["privacy_use"] = True
            if "processes" in content: perm_flags["processes_use"] = True
            if "proxy" in content: perm_flags["proxy_use"] = True
            if "sessions" in content: perm_flags["sessions_use"] = True
            if "tabCapture" in content: perm_flags["tabCapture_use"] = True
            if "topSites" in content: perm_flags["topSites_use"] = True
            if "tabs" in content: perm_flags["tabs_use"] = True
            if "webAuthenticationProxy" in content: perm_flags["webAuthenticationProxy_use"] = True
            if "webNavigation" in content: perm_flags["webNavigation_use"] = True

        #--------------------READING SUSPICIOUS FILE CONTENT---------------------------
        found_keywords = [keyword for keyword in file_access_keywords if keyword in content]
        if found_keywords:
            perm_flags["file_reading"] = True
            # print(f"{found_keywords} found in the file {file_path}!\n")

        #Cheking for fingerprinting
        for pattern in fingerprint_patterns:
            if re.search(pattern, content):
                found_fingerprint.add(pattern)
        
        #eval usage
        for pattern in eval_patterns:
            match = re.search(pattern, content)
            if match:
                other_flags["eval_use"] = True

        for pattern in listener_patterns:
            match = re.search(pattern, content)
            if match:
                # print(f"Matched: {match.group()} in file {file_path}")
                other_flags["sus_listener"] = True




def evaluateMalicious():
    num_of_shady_permissions = len([perm for perm in perm_flags.keys() if perm_flags[perm]])
    if num_of_shady_permissions > 5:
        perm_flags["too_many_permissions"] = True

    for permission in fingerprint_permissions:
        if perm_flags[permission]:
            found_fingerprint.add(permission) 
    if len(found_fingerprint)>8:
        other_flags["fingerprint_high"] = True
    elif len(found_fingerprint)>5:
        other_flags["fingerprint_medium"] = True
    elif len(found_fingerprint)>2:
        other_flags["fingerprint_low"] = True
        


def reportMalicious():

    flag_messages = {
    "fingerprint_low": f"‣ This extension collects some device or browser characteristics that could be used for tracking.\n\tDetails collected:\n\t{found_fingerprint}",
    "fingerprint_medium": f"‣ This extension collects a lot of browser and device details. This data can be used for profiling.\n\tDetails collected:\n\t{found_fingerprint}",
    "fingerprint_high": f"‣ This extension collects an extensive amount of fingerprinting data. This extension might be profiling you or selling your data.\n\tDetails collected:\n\t{found_fingerprint}",
    "too_many_permissions": "‣ This extension uses too many suspicious permissions. Unless it is a complex extension, this is highly suspicious.",
    "eval_use": "‣ This extension uses eval(). That is highly suspicious.",
    "sus_listener": "‣ This extension registers event listeners for sensitive browser actions like keyboard, clipboard, or tab activity.",
    }


    perm_messages = {
    "gcm_use": "‣ This extension can receive remote commands from an external server using Google's push messaging system (GCM). If the extension is not clearly advertized to provide real-time updates or messages, this is highly suspicious.",
    "fileSystemProvider_use": "‣ This extension deals with remote files. Use it cautiously.",
    "file_reading": "‣ This extension can read submitted files! Avoid exposing sensitive data.",
    "clipboard_use": "‣ This extension can read or modify clipboard content. If unnecessary, it could be used to steal copied information.",
    "settings_use": "‣ This extension modifies browser content settings. This could weaken security or allow unwanted behavior.",
    "debugger_use": "‣ This extension uses the debugger API, which allows full DevTools access to any tab. This is extremely dangerous unless it’s a trusted developer tool.",
    "declarativeNetRequest_use": "‣ This extension intercepts or redirects browser traffic using static rules. If it modifies traffic from trusted sites, it may be a phishing attempt.",
    "desktopCapture_use": "‣ This extension can record your screen or window. If it’s not a known screen-sharing tool, this is a privacy risk.",
    "downloads_use": "‣ This extension can download and automatically open files. This can be used to download viruses unless it is from a trusted source.",
    "management_use": "‣ This extension can list, disable, or remove other extensions. This is very powerful and should be treated with suspicion.",
    "notifications_use": "‣ This extension can create desktop notifications. If used for phishing or scam alerts, this could be dangerous.",
    "privacy_use": "‣ This extension can change your browser’s privacy settings. If misused, it can reduce your protection against tracking and data leaks.",
    "proxy_use": "‣ This extension can change your proxy settings, potentially rerouting your internet traffic through malicious servers. Treat this with extreme caution unless it’s a trusted VPN.",
    "sessions_use": "‣ This extension can access recently closed tabs and browsing sessions across your signed-in devices. Combined with other permissions, this can be used for detailed tracking.",
    "tabCapture_use": "‣ This extension can record audio or video from a browser tab. If it’s not clearly a screen recording tool, this poses a major privacy risk.",
    "tabs_use": "‣ This extension can read and manipulate your browser tabs. This can be used for surveillance or phishing.",
    "webAuthenticationProxy_use": "‣ This extension can intercept login credentials via authentication proxying. This is extremely dangerous outside enterprise environments.",
    "webNavigation_use": "‣ This extension monitors your browsing activity, including redirects and page loads. Often used for behavior tracking."
}


    for flag, message in flag_messages.items():
        if other_flags.get(flag):
            print("\n" + message)
    
    print("\nPERMISSIONS")

    for flag, message in perm_messages.items():
        if perm_flags.get(flag):
            print("\n" + message)
        



def main():
    print("\nParsing files...")
    scanFolder(sys.argv[1])
    print("Parsing finished.\n")

    evaluateMalicious()

    print("-"*50 + "\n")
    print("RESULTS:")
    reportMalicious()
    print("\n" + "-"*50)




if __name__ == "__main__":
    main()
