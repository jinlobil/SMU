import unittest
from datetime import date

try:
    from web_backend.app import _range
except ModuleNotFoundError as exc:
    _range = None
    MISSING_DEPENDENCY = str(exc)
else:
    MISSING_DEPENDENCY = ""


@unittest.skipIf(_range is None, f"optional web dependency unavailable: {MISSING_DEPENDENCY}")
class DateRangeTests(unittest.TestCase):
    def test_explicit_range(self):
        self.assertEqual(_range(date(2026, 1, 1), date(2026, 1, 7)), ("2026-01-01", "2026-01-07"))

    def test_default_range_is_seven_days(self):
        start, end = _range(None, date(2026, 1, 7))
        self.assertEqual((start, end), ("2026-01-01", "2026-01-07"))
