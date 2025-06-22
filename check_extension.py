import os, sys
import re

#dangerous keywords to look for:
file_access_keywords = ["FileReader", "readAsText", "readAsDataURL", "readAsBinaryString",
                         "readAsArrayBuffer", "fetch("]
fingerprint_patterns = [
    r"getImageData\s*\(",
    r"toDataURL\s*\(",
    r"AudioContext",
    r"OscillatorNode",
    r"getFloatFrequencyData",
    r"navigator\.hardwareConcurrency",
    r"navigator\.deviceMemory",
    r"navigator\.plugins",
    r"navigator\.languages",
    r"screen\.(width|height)",
    r"chrome\.processes\.getProcessIdForTab\s*\(",
    r"chrome\.processes\.getProcessInfo\s*\(",
    r"chrome\.processes\.terminate\s*\(",
    r"chrome\.processes\b"
]


def main():
    print("-"*50)
    print("Parsing files...\n")

    scanFolder(sys.argv[1])

    print("\nParsing finished.")
    print("-"*50)



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
            print(f"{found_keywords} found in the file {file_path}!\n")


        #Cheking for fingerprinting
        count = 0
        for pattern in fingerprint_patterns:
            if re.search(pattern, content):
                count+=1
        if count > 3:
            print ("This extension collects a broad range of device and browser details, " \
            "which may be used for tracking.")
        

        #----------------------- PERMISSIONS -----------------------------------
        #Checking if it uses VPN
        if filename == "manifest.json" and "vpnProvider" in content:
            print(f"This file uses VPN: {file_path}")
            print("If this extension is not advertized as a VPN provider and does not come" \
            " from a trusted source, this is highly suspicious.")
        
        
        



if __name__ == "__main__":
    main()