# Browser Extension Checker -- Prava

A terminal application for analyzing browser extensions and detecting potentially malicious behavior.

---

## Features

- **Certificate Integrity Check** for Chrome, Firefox, Safari
- **Malicious Pattern Detection**:
  - `eval()` usage
  - Suspicious or hidden event listeners
  - Cookie access or theft
  - Unsolicited network requests
  - Redirection or injection
- **File Access Check**
- **Permission Check**
- **Input Access Auditing**

---
1. **cookie theft detection**

    create a python script that will analyze all JavaScript files in a browser extension and search for attempts to access browser cookies.

2. **eval() detection**

    write a python script that scans for dangerous JavaScript function eval(), which is known for enabling arbitrary code execution.

3. **suspicious event listener detection**

    create a python script that will analyze all JavaScript files for suspicious or excessive use of event listeners—especially ones that hook into sensitive input fields or system-wide events




## **Tools**:

- **Language**: Python 3
