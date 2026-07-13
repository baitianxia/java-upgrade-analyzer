import io
import unittest

from scripts import safe_xml


class SafeXmlTest(unittest.TestCase):
    def test_rejects_doctype_and_entity_declarations(self):
        payload = b'<!DOCTYPE x [<!ENTITY boom "expanded">]><x>&boom;</x>'

        with self.assertRaises(safe_xml.ParseError):
            safe_xml.fromstring(payload)
        with self.assertRaises(safe_xml.ParseError):
            safe_xml.parse(io.BytesIO(payload))

    def test_preserves_elementtree_compatible_parse_api(self):
        root = safe_xml.fromstring(b'<project><artifactId>demo</artifactId></project>')
        tree = safe_xml.parse(io.BytesIO(b'<project><groupId>g</groupId></project>'))

        self.assertEqual(root.findtext('artifactId'), 'demo')
        self.assertEqual(tree.getroot().findtext('groupId'), 'g')


if __name__ == '__main__':
    unittest.main()
