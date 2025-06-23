#dangerous keywords to look for:


file_access_keywords = ["FileReader", "readAsText", "readAsDataURL", "readAsBinaryString",
                         "readAsArrayBuffer", "fetch("]


fingerprint_patterns = [
    #canvas
    r"\.getImageData\s*\(",
    r"\.toDataURL\s*\(",
    #audio 
    r"AudioContext",
    r"OscillatorNode",
    r"getFloatFrequencyData",
    #navigator
    r"navigator\.hardwareConcurrency",
    r"navigator\.deviceMemory",
    r"navigator\.plugins",
    r"navigator\.languages",
    #screen
    r"screen\.(width|height)"
    #time (can specify timezone)
    r"new\s+Date\s*\("
    r"Intl\.DateTimeFormat\s*\("
    #the bottow ones are permissons, but only used for fingerpringing
    r"chrome\.topSites\.get\s*\("
    r"chrome\.system\.cpu\.getInfo\s*\("
    r"chrome\.system\.memory\.getInfo\s*\("
    r"chrome\.system\.display\.getInfo\s*\("
]

fingerprint_permissions = {"processes_use", "tabs_use", "topSites_use", "history_use", 
                           "cookies_use", "identity_use"}
