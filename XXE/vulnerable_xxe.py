from flask import Flask, request
from lxml import etree

app = Flask(__name__)

# A simple HTML form for submitting XML data
HTML_FORM = """
<!DOCTYPE html>
<html>
<head>
    <title>XXE Vulnerable App</title>
    <style>
        body { font-family: sans-serif; background-color: #fff5f5; }
        .container { max-width: 600px; margin: 50px auto; padding: 20px; border: 1px solid #e57373; border-radius: 8px; background-color: white;}
        textarea { width: 100%; box-sizing: border-box; }
        pre { background-color: #f1f1f1; padding: 10px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ Vulnerable XXE Parser</h1>
        <p>This application parses XML using a dangerously configured parser. Try submitting an XXE payload to read a local file.</p>
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
    # Using a templating engine is safer, but for this simple example,
    # we'll use string replacement and ensure user content is escaped.
    return HTML_FORM.replace("{% if result %}", "").replace("{{ result }}", "").replace("{% endif %}", "")

@app.route('/process', methods=['POST'])
def process_xml():
    xml_data = request.form.get('xml_data', '')
    if not xml_data:
        return HTML_FORM.replace("{% if result %}", "{% if result %}").replace("{{ result }}", "Error: No XML data submitted.").replace("{% endif %}", "{% endif %}"), 400

    try:
        # VULNERABLE: The parser is configured to resolve external entities.
        # This is the source of the XXE vulnerability.
        parser = etree.XMLParser(resolve_entities=True)
        root = etree.fromstring(xml_data.encode(), parser)
        result = etree.tostring(root, pretty_print=True).decode()
    except Exception as e:
        result = f"Error parsing XML: {e}"

    # Simple rendering for the example
    rendered_html = HTML_FORM.replace("{% if result %}", "").replace("{% endif %}", "")
    # Basic escaping to prevent the result from being interpreted as HTML
    safe_result = result.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    rendered_html = rendered_html.replace("{{ result }}", safe_result)
    
    return rendered_html

if __name__ == '__main__':
    print("Starting vulnerable server on http://127.0.0.1:5001")
    app.run(debug=True, port=5001)