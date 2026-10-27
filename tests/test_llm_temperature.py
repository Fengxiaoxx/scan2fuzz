"""The OPENCODE_TEMPERATURE knob used when a call does not name a temperature."""

from __future__ import annotations

import unittest

from src.llm.opencode_query import temperature_from_environment


class TemperatureFromEnvironmentTests(unittest.TestCase):
    def test_unset_or_empty_keeps_the_provider_default(self):
        self.assertIsNone(temperature_from_environment({}))
        self.assertIsNone(temperature_from_environment({"OPENCODE_TEMPERATURE": "  "}))

    def test_a_number_is_used(self):
        self.assertEqual(temperature_from_environment({"OPENCODE_TEMPERATURE": "0.3"}), 0.3)
        self.assertEqual(temperature_from_environment({"OPENCODE_TEMPERATURE": "0"}), 0.0)

    def test_a_bad_value_is_refused(self):
        for raw in ("abc", "-1", "inf", "nan"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    temperature_from_environment({"OPENCODE_TEMPERATURE": raw})


if __name__ == "__main__":
    unittest.main()
