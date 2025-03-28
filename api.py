from fastapi import FastAPI, Request
import re
import json

app = FastAPI()

COMMON_ATTACK_KEYWORDS = [
    "SELECT", "DROP", "UNION", "INSERT", "DELETE", "UPDATE",  # SQL Injection
    "<script>", "onerror=", "alert(", "eval(", "javascript:",  # XSS
    "wget", "curl", "nc", "ncat", "chmod", "exec(", "system(",  # Command Injection
    "botnet", "flood", "slowloris", "DOS",                      # DDoS
    "../", "/etc/passwd", "/proc/self",                         # LFI/RFI
    "base64_decode(", "phpinfo()",                              # PHP Code Injection
    "Bearer ", "API_KEY=", "Authorization:", "Set-Cookie:",     # API Attacks
]

ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(?i)(or\s+1=1)", 
        r"(?i)(union\s+select)",
        r"(?i)(select\s+\*\s+from)",
        r"(?i)(insert\s+into\s+\w+\s+values)",
        r"(?i)(drop\s+table\s+\w+)"
    ],
    "Cross-Site Scripting (XSS)": [
        r"<script>.*</script>", 
        r"(?i)(onerror\s*=)",
        r"(?i)(alert\s*\()",
        r"(?i)(document\.cookie)",
        r"(?i)(javascript:\s*)"
    ],
    "Command Injection": [
        r"(?i)(wget\s+http)", 
        r"(?i)(curl\s+-o)", 
        r"(?i)(nc\s+-e\s+/bin/sh)",
        r"(?i)(;.*rm\s+-rf\s+/)",
        r"(?i)(&&\s*echo\s*root)"
    ],
    "DDoS Attack Indicators": [
        r"(?i)(botnet)", 
        r"(?i)(slowloris)", 
        r"(?i)(http flood)",
        r"(?i)(rate limit bypass)",
        r"(?i)(SYN flood)"
    ],
    "LFI (Local File Inclusion)": [
        r"(?i)(\.\./\.\./)", 
        r"(?i)(/etc/passwd)",
        r"(?i)(/proc/self/environ)"
    ],
    "RFI (Remote File Inclusion)": [
        r"(?i)(http://.*\.php)", 
        r"(?i)(https://.*\.php)",
        r"(?i)(php://input)"
    ],
    "API Attack": [
        r"(?i)(Bearer\s+[A-Za-z0-9-_]+)", 
        r"(?i)(Authorization:\s*Bearer)",
        r"(?i)(api_key=[A-Za-z0-9-_]+)"
    ],
}

def keyword_match(payload_str):
    """Checks if the payload contains common attack keywords."""
    for keyword in COMMON_ATTACK_KEYWORDS:
        if keyword.lower() in payload_str.lower():
            return True 
    return False  

def dpi_analysis(payload_str):
    """Scans for known attack patterns using regex."""
    detected_attacks = {}
    
    for attack_type, patterns in ATTACK_PATTERNS.items():
        matches = [pattern for pattern in patterns if re.search(pattern, payload_str)]
        if matches:
            detected_attacks[attack_type] = matches
    
    if detected_attacks:
        return {
            "status": "Blocked",
            "reason": "Confirmed Malicious Request",
            "attacks_detected": detected_attacks
        }
    
    return {
        "status": "Potential Threat",
        "message": "Suspicious but no known attack detected",
        "classification": "Unknown Attack"
    }

@app.post("/predict/")
async def detect_attack(request: Request):
    try:
        payload = await request.json()
        payload_str = json.dumps(payload)

        if keyword_match(payload_str):
            dpi_result = dpi_analysis(payload_str)
            return dpi_result

        return {"status": "Allowed", "message": "Request is safe"}

    except Exception as e:
        return {"error": str(e)}
