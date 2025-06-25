#dangerous keywords to look for:


file_access_keywords = ["FileReader", "readAsText", "readAsDataURL", "readAsBinaryString",
                         "readAsArrayBuffer", "fetch("]


fingerprint_patterns = [
    # canvas
    r"\.getImageData\s*\(",
    r"\.toDataURL\s*\(",
    # audio 
    r"AudioContext",
    r"OscillatorNode",
    r"getFloatFrequencyData",
    # navigator
    r"navigator\.hardwareConcurrency",
    r"navigator\.deviceMemory",
    r"navigator\.plugins",
    r"navigator\.languages",
    # screen
    r"screen\.(width|height)",
    # time (can specify timezone)
    r"new\s+Date\s*\(",
    r"Intl\.DateTimeFormat\s*\(",
    # the bottom ones are permissions, but only used for fingerprinting
    r"chrome\.topSites\.get\s*\(",
    r"chrome\.system\.cpu\.getInfo\s*\(",
    r"chrome\.system\.memory\.getInfo\s*\(",
    r"chrome\.system\.display\.getInfo\s*\(",
]

fingerprint_permissions = {"processes_use", "tabs_use", "topSites_use", "history_use", 
                           "cookies_use", "identity_use", "declarativeNetRequestFeedback_use", "geolocation_use"}

eval_patterns = [
    r"eval\s*\(\s*.*(fetch|XMLHttpRequest|axios|http[s]?:)",
    r"eval\s*\(\s*.*(decodeURIComponent|atob|btoa|unescape|JSON\.parse)",
    r"eval\s*\(\s*.*(\+|\.join|\.concat|template\s*=\s*`)",
    r"eval\s*\(\s*['\"]?[a-zA-Z0-9+/\\=]{16,}['\"]?\s*\)",
    r"set(?:Timeout|Interval)\s*\(\s*['\"`]\s*eval",
    r"new Function\s*\(\s*.*(fetch|XMLHttpRequest|decode|join|concat)",
]

listener_patterns = [
    r"addEventListener\s*\(\s*['\"](copy|paste|cut|keydown|keypress|keyup)['\"]",
    r"addEventListener\s*\(\s*['\"](mousemove|mousedown|mouseup|click)['\"]",
    r"chrome\.runtime\.onMessage\.addListener",
    r"chrome\.webNavigation\.on.*\.addListener",
    r"chrome\.tabs\.on.*\.addListener"
]

# known_safe_libs = [
#     "bluebird", "lodash", "jquery", "moment", "dayjs",
#     "zepto", "require.js", "browserify", "webpack",
#     "underscore", "react", "vue", "angular", "zone.js"
# ]