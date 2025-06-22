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
found_fingerprint = set()

# flags for malicious activities
flags = {
    "file_reading": False,
    "fingerprint": False,
    "fileSystemProvider_use": False,
    "gcm_use": False,
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
        #Checking if it uses fileSystemProvider
        if filename == "manifest.json" and "fileSystemProvider" in content:
            flags["fileSystemProvider_use"] = True
            # print(f"This file uses fileSystemProvider: {file_path}")
            
        #Checking if it uses gcm
        if filename == "manifest.json" and "gcm" in content:
            flags["gcm_use"] = True
            # print(f"This file uses GCM: {file_path}")
            
        

def reportMalicious():
    if flags["gcm_use"] == True:
        print("\n‣ This extension is can receive remote commands from an external server " \
            "using Google's push messaging system (GCM). If the extension is not clearly advertized " \
            "to provide real-time updates or messages, this is hightly suspicious.")
        
    if flags["fileSystemProvider_use"] == True:
        print("\n‣ This extension deals with remote files, make sure to use" \
                " it causiously .")
        
    if flags["fingerprint"] == True:
        print (f"\n‣ This extension collects a broad range of device and browser details, " \
            f"which may be used for tracking. \n\tThe details collected are: \n {found_fingerprint}")

    
    if flags["file_reading"] == True:
        print ("\n‣ This extencion can read submitted files! Do not expose any sensitive information on them.")
        



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
