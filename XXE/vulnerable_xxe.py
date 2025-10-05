# secure_lxml.py
from flask import Flask, request, Response
from lxml import etree

app = Flask(__name__)

def make_safe_parser():
    # Disallow DTD, external entities, network access and entity resolution.
    return etree.XMLParser(
        resolve_entities=False,  # DO NOT resolve external entities
        load_dtd=False,          # Do not load DTD
        no_network=True,         # Prevent fetching external resources
        huge_tree=False          # avoid huge/DoS-ish trees
    )

@app.route('/process', methods=['POST'])
def process_xml():
    content_type = request.headers.get('Content-Type', '')
    if 'application/xml' not in content_type:
        return 'Error: Content-Type must be application/xml', 400

    xml_data = request.get_data()
    if not xml_data:
        return 'Error: No XML data received', 400

    try:
        parser = make_safe_parser()
        # If there is a DTD or external entity, parser will not load/resolve them.
        doc = etree.fromstring(xml_data, parser)

        message_element = doc.find('message')
        if message_element is not None and message_element.text is not None:
            # safe: entity expansions will not be resolved to local files
            return Response(f"Received message: {message_element.text}", mimetype='text/plain')
        else:
            return "XML parsed, but no 'message' element or empty content.", 400

    except etree.XMLSyntaxError as e:
        # don't leak internal details in production — this is for debugging
        return f"XML Error: {e}", 400
    except Exception as e:
        return f"An unexpected error occurred: {e}", 500

if __name__ == '__main__':
    print("✅ Secure XXE-protected server started on http://127.0.0.1:5000")
    app.run(port=5000)
