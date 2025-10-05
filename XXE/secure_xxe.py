from flask import Flask, request
from defusedxml import lxml as safe_lxml

app = Flask(__name__)

# A simple HTML form for submitting XML data
HTML_FORM = """
<!DOCTYPE html>
<html>
<head>
    <title>XXE Secure App</title>
    <style>
        body { font-family: sans-serif; background-color: #f5fff5; }
        .container { max-width: 600px; margin: 50px auto; padding: 20px; border: 1px solid #73e573; border-radius: 8px; background-color: white;}
        textarea { width: 100%; box-sizing: border-box; }
        pre { background-color: #f1f1f1; padding: 10px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ Secure XML Parser</h1>
        <p>This application uses <code>defusedxml</code> to safely parse XML. Submitting an XXE payload will result in an error or empty entity.</p>
        <form action="/process" method="post">
            <textarea name="xml_data" rows="10" cols="50" placeholder="Enter XML here..."></textarea><br><br>
            <input type="submit" value="Process XML">
        </form>
        {% if result %}
            <h2>Result:</h2>
            <pre>{{ result }}</pre>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def index():
    return HTML_FORM.replace("{% if result %}", "").replace("{{ result }}", "").replace("{% endif %}", "")

@app.route('/process', methods=['POST'])
def process_xml():
    xml_data = request.form.get('xml_data', '')
    if not xml_data:
        return HTML_FORM.replace("{% if result %}", "{% if result %}").replace("{{ result }}", "Error: No XML data submitted.").replace("{% endif %}", "{% endif %}"), 400

    try:
        # SECURE: Using defusedxml.lxml.fromstring which disables external
        # entity processing by default.
        root = safe_lxml.fromstring(xml_data.encode())
        result = safe_lxml.tostring(root, pretty_print=True).decode()
    except Exception as e:
        result = f"Invaid Input"

    # Simple rendering for the example
    rendered_html = HTML_FORM.replace("{% if result %}", "").replace("{% endif %}", "")
    # Basic escaping
    safe_result = result.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    rendered_html = rendered_html.replace("{{ result }}", safe_result)

    return rendered_html

if __name__ == '__main__':
    print("Starting secure server on http://127.0.0.1:5002")
    app.run(debug=True, port=5002)