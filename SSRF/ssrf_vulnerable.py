# Deliberately vulnerable SSRF example (educational use only)

from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/ssrf")
def ssrf():
    # Take user-supplied URL directly from query string
    target_url = request.args.get("url")

    if not target_url:
        return "Please provide a ?url= parameter", 400

    # 🚨 Vulnerable: No validation of user input
    r = requests.get(target_url)
    return r.text

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=6000, debug=True)
