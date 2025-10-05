# app.py
import sys
from lxml import etree
from flask import Flask, request, Response
import logging

logging.basicConfig(level=logging.INFO)
app = Flask(__name__)

class SecurityException(Exception):
    pass

xsd_schema_str = """
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="data">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="message" type="xs:string"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>
"""
xml_schema = etree.XMLSchema(etree.fromstring(xsd_schema_str.encode('utf-8')))

@app.route('/process', methods=['POST'])
def process_xml_generic():
    xml_data = request.get_data()
    if not xml_data:
        return 'Error: No XML data received', 400

    try:
        # Secure parser blocks XXE by disabling entities and stripping DTDs
        parser = etree.XMLParser(resolve_entities=False, strip_dtd=True)
        
        doc = etree.fromstring(xml_data, parser)
        xml_schema.assertValid(doc)
        
        message_element = doc.find('message')
        response_text = f"Received valid message: {message_element.text}"
        return Response(response_text, mimetype='text/plain')

    except (etree.XMLSyntaxError, etree.DocumentInvalid) as e:
        logging.warning(f"Security risk blocked. Original error: {e}")
        raise SecurityException("Security risk detected in XML input.")
    except SecurityException as e:
        return str(e), 400
    except Exception as e:
        logging.error(f"An unexpected server error occurred: {e}")
        return "An internal server error occurred.", 500

if __name__ == '__main__':
    print(f"--- Python Interpreter: {sys.executable}")
    print(f"--- lxml Version: {etree.LXML_VERSION}")
    print("🚀 Secure Server started on http://127.0.0.1:5001")
    app.run(port=5001)