"""Operator tool_loops behavior that a live loop depends on."""
import sys
import unittest
from unittest.mock import Mock

import tool_loops as tl


class ChildOutputTest(unittest.TestCase):
    def test_a_cli_child_printing_non_ascii_text_succeeds_and_round_trips(self):
        # Stage outputs carry text such as arrows and dashes. On Windows a piped child encodes its
        # stdout with the locale code page unless told otherwise; one such character halted a
        # whole filmed round (driver error: UnicodeEncodeError).
        text = 'stage handoff \u2192 claim \u2014 \u201cquoted\u201d \u2026'
        child = [sys.executable, '-c', f'import json; print(json.dumps({{"note": {text!r}}}, ensure_ascii=False))']
        rc, out, err = tl.tcli(lane=Mock(temporal_cli=lambda: child))
        self.assertEqual(rc, 0, err)
        self.assertIn(text, out)


if __name__ == '__main__':
    unittest.main()
