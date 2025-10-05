# Python XXE Vulnerability and Mitigation Example

This project demonstrates an XML External Entity (XXE) vulnerability in a simple Python Flask application and shows how to mitigate it using the `defusedxml` library.

## Project Structure

```
.
├── vulnerable_xxe.py   # The Flask app with the XXE vulnerability
├── secure_xxe.py       # The fixed Flask app using defusedxml
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

## Setup and Installation

**Install the required packages:**

 ```bash
pip install -r requirements.txt
 ```

## How to Run the Demo

You can run both servers simultaneously in separate terminal windows to compare their behavior.

### 1. Run the Vulnerable Application

Start the server that contains the XXE vulnerability.

```bash
python vulnerable_xxe.py
```
Navigate to **http://127.0.0.1:5001** in your browser.

#### Test the Vulnerability

Paste the following **malicious XML payload** into the text area. This payload defines an external entity `xxe` that points to the `/etc/passwd` file on a Linux/macOS system. (On Windows, you could try `file:///c:/boot.ini`).

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
    <item>&xxe;</item>
</data>
```

When you click "Process XML", the vulnerable application will replace `&xxe;` with the contents of the `/etc/passwd` file and display it on the page.



### 2. Run the Secure Application

Start the secure server that correctly handles XML parsing.

```bash
python secure_xxe.py
```
Navigate to **http://127.0.0.1:5002** in your browser.

#### Test the Fix

Submit the **same malicious payload** as before.

This time, the `defusedxml` library will either raise an exception or simply parse the entity as an empty string, refusing to access the local file. The contents of `/etc/passwd` will **not** be displayed. This demonstrates that the vulnerability has been successfully mitigated.



## The Fix Explained

The vulnerability exists in `vulnerable_app.py` because the `lxml` parser is explicitly configured to be insecure:
`parser = etree.XMLParser(resolve_entities=True)`

The solution is simple. In `secure_app.py`, we replace the vulnerable parser with `defusedxml`, which is secure by default:
`from defusedxml import lxml as safe_lxml`
`root = safe_lxml.fromstring(xml_data.encode())`

**Rule of thumb:** Always use `defusedxml` when parsing any XML from an untrusted source in Python.