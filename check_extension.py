import os, sys
import re
from patterns_and_keywords import *

found_fingerprint = set()

# flags for malicious activities
flags = {
    "file_reading": False,
    "fingerprint": False,
    "fileSystemProvider_use": False,
    "gcm_use": False,
    "cookie_use": False,
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
    "proxy": False,
    "sessions_use": False,
    "tabCapture_use": False,
    "topSites_use": False,
    "tabs_use": False,
    "webAuthenticationProxy_use": False,
    "webNavigation_use": False,
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
        #--------------------READING THE CONTENT HERE---------------------------
        #checks if it reads submitted files
        content = f.read()
        found_keywords = [keyword for keyword in file_access_keywords if keyword in content]
        if found_keywords:
            flags["file_reading"] = True
            # print(f"{found_keywords} found in the file {file_path}!\n")


        #Cheking for fingerprinting
        count = 0
        for pattern in fingerprint_patterns:
            if re.search(pattern, content):
                count+=1
                found_fingerprint.add(pattern)
        if count > 3:
            flags["fingerprint"] = True
            

        #-------------------------- PERMISSIONS --------------------------------
        if filename == "manifest.json":
            if "fileSystemProvider" in content:
                flags["fileSystemProvider_use"] = True
                # print(f"This file uses fileSystemProvider: {file_path}")
            if "gcm" in content:
                flags["gcm_use"] = True
                # print(f"This file uses GCM: {file_path}")
            if "cookies" in content:
                flags["cookie_use"] = True
                found_fingerprint.add("cookies")
                # print(f"This file uses cookies: {file_path}")

            
            #Now for permissions that chrome commonly warns about:
            if "clipboardRead" in content: flags["clipboard_use"] = True
            if "contentSettings" in content: flags["settings_use"] = True
            if "debugger" in content: flags["debugger_use"] = True
            if "clipboardRead" in content: flags["clipboard_use"] = True
            if "declarativeNetRequest" in content: flags["declarativeNetRequest_use"] = True
            if "declarativeNetRequestFeedback" in content: flags["declarativeNetRequestFeedback_use"] = True
            if "desktopCapture" in content: flags["desktopCapture_use"] = True
            if "downloads" in content: flags["downloads_use"] = True
            if "geolocation" in content: flags["geolocation_use"] = True
            if "history" in content: flags["history_use"] = True
            if "identity" in content: flags["identity_use"] = True
            if "management" in content: flags["management_use"] = True
            if "notifications" in content: flags["notifications_use"] = True
            if "privacy" in content: flags["privacy_use"] = True
            if "processes" in content: flags["processes_use"] = True
            if "proxy" in content: flags["proxy_use"] = True
            if "sessions" in content: flags["sessions_use"] = True
            if "tabCapture" in content: flags["tabCapture_use"] = True
            if "topSites" in content: flags["topSites_use"] = True
            if "tabs" in content: flags["tabs_use"] = True
            if "webAuthenticationProxy" in content: flags["webAuthenticationProxy_use"] = True
            if "webNavigation" in content: flags["webNavigation_use"] = True
            
            
        

def reportMalicious():
    flag_messages = {
    "gcm_use": "‣ This extension can receive remote commands from an external server using Google's push messaging system (GCM). If the extension is not clearly advertized to provide real-time updates or messages, this is highly suspicious.",
    "fileSystemProvider_use": "‣ This extension deals with remote files. Use it cautiously.",
    "fingerprint": f"‣ This extension collects a broad range of device and browser details, which may be used for tracking.\n\tDetails collected:\n\t{found_fingerprint}",
    "file_reading": "‣ This extension can read submitted files! Avoid exposing sensitive data.",
    "cookie_use": "‣ This extension uses cookies. Be careful if paired with external communication.",
    "clipboard_use": "‣ This extension can read or modify clipboard content. If unnecessary, it could be used to steal copied information.",
    "settings_use": "‣ This extension modifies browser content settings. This could weaken security or allow unwanted behavior.",
    "debugger_use": "‣ This extension uses the debugger API, which allows full DevTools access to any tab. This is extremely dangerous unless it’s a trusted developer tool.",
    "declarativeNetRequest_use": "‣ This extension intercepts or redirects browser traffic using static rules. If it modifies traffic from trusted sites, it may be a phishing attempt.",
    "declarativeNetRequestFeedback_use": "‣ This extension monitors which URLs trigger blocking rules. This could be used to track your browsing behavior.",
    "desktopCapture_use": "‣ This extension can record your screen or window. If it’s not a known screen-sharing tool, this is a privacy risk.",
    "downloads_use": "‣ This extension can download and automatically open files. This can be used to drop and trigger malicious payloads.",
    "geolocation_use": "‣ This extension accesses your physical location. Be cautious unless this is part of its core functionality.",
    "history_use": "‣ This extension reads your full browsing history. This is often unnecessary and could be used to track behavior.",
    "identity_use": "‣ This extension can access your Google identity, including email and account ID. It may also request OAuth2 tokens to access services like Gmail or Drive.",
    "management_use": "‣ This extension can list, disable, or remove other extensions. This is very powerful and should be treated with suspicion.",
    "notifications_use": "‣ This extension can create desktop notifications. If used for phishing or scam alerts, this could be dangerous.",
    "privacy_use": "‣ This extension can change your browser’s privacy settings. If misused, it can reduce your protection against tracking and data leaks.",
    "processes_use": "‣ This extension can access detailed system and browser process information. This may be used for fingerprinting or profiling.",
    "proxy": "‣ This extension can change your proxy settings, potentially rerouting your internet traffic through malicious servers. Treat this with extreme caution unless it’s a trusted VPN.",
    "sessions_use": "‣ This extension can access recently closed tabs and browsing sessions across your signed-in devices. Combined with other permissions, this can be used for detailed tracking.",
    "tabCapture_use": "‣ This extension can record audio or video from a browser tab. If it’s not clearly a screen recording tool, this poses a major privacy risk.",
    "topSites_use": "‣ This extension reads a list of your most frequently visited sites. This may be used to build a profile of your browsing habits.",
    "tabs_use": "‣ This extension can read and manipulate your browser tabs. Combined with other permissions, this can be used for surveillance or phishing.",
    "webAuthenticationProxy_use": "‣ This extension can intercept login credentials via authentication proxying. This is extremely dangerous outside enterprise environments.",
    "webNavigation_use": "‣ This extension monitors your browsing activity, including redirects and page loads. Often used for behavior tracking."
}


    for flag, message in flag_messages.items():
        if flags.get(flag):
            print("\n" + message)
        



def main():
    print("\nParsing files...")

    scanFolder(sys.argv[1])

    print("Parsing finished.\n")
    print("-"*50 + "\n")
    print("RESULTS:")

    reportMalicious()

    print("\n" + "-"*50)




if __name__ == "__main__":
    main()
