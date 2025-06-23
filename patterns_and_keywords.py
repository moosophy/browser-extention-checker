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
    r"screen\.(width|height)"
]
