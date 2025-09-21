# 🛡️ SSRF Demo (Vulnerable vs Secure)

This repository demonstrates a **Server-Side Request Forgery (SSRF)** vulnerability in Python (Flask), and how to secure against it.  
⚠️ **Important**: The vulnerable code is for **educational use only**. Do **not** expose it to the internet or deploy in production.  

---

## 📂 Files
- `ssrf_vulnerable.py` → Deliberately insecure version  
- `ssrf_secure.py` → Hardened, safe version with mitigations  

---

## 🚀 Prerequisites
- Python 3.7+  
- Install dependencies:
  ```bash
  pip install flask requests

🧪 Running the Vulnerable SSRF App
1. Start the server
python3 ssrf_vulnerable.py


The app will listen on: http://127.0.0.1:5000

2. Normal usage (fetch an external site)
curl "http://127.0.0.1:5000/ssrf?url=http://example.com"

3. Simulate SSRF attack with internal service

Start a dummy “internal” service:

python3 -m http.server 8000


This serves files from your current directory at http://127.0.0.1:8000.

Exploit SSRF:

curl "http://127.0.0.1:5000/ssrf?url=http://127.0.0.1:8000/"


✅ You should see a directory listing from port 8000.

4. Simulate attacker reading a secret file

Create a fake secret file:

echo "TOP SECRET DATA" > secret.txt


Access it through the vulnerable app:

curl "http://127.0.0.1:5000/ssrf?url=http://127.0.0.1:8000/secret.txt"


Output:

TOP SECRET DATA

🔒 Running the Secure SSRF App
1. Start the server
python3 ssrf_secure.py


The app will listen on: http://127.0.0.1:5001

2. Allowed request (allowlisted domain)
curl "http://127.0.0.1:5001/safe_fetch?url=https://example.com"

3. Blocked request (internal service)
curl "http://127.0.0.1:5001/safe_fetch?url=http://127.0.0.1:8000/"


Response:

Blocked unsafe destination

4. Blocked request (non-allowlisted domain)
curl "http://127.0.0.1:5001/safe_fetch?url=https://google.com"


Response:

Domain not allowed

🔑 Key Takeaways

❌ Vulnerable app allows fetching any URL, including internal services or files.

✅ Secure app enforces:

Allowlist of domains

Private/loopback IP blocking

Timeouts & no redirects

📊 Attack Flow
[Attacker] 
     |
     v
[Vulnerable SSRF App] ----> [Internal Service / Secret File]  ✅ Allowed

[Attacker] 
     |
     v
[Secure SSRF App] ----> [Internal Service]  ❌ Blocked