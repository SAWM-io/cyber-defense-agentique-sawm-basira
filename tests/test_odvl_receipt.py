"""Le classement public ODVL et son observation ont des recus distincts."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from controleur.validation_acces_exterieur import odvl_applied


class OdvlReceiptTests(unittest.TestCase):
    def test_ranking_receipt_requires_no_observation_available_field(self):
        self.assertTrue(odvl_applied({
            "schema": "basira-odvl-ranking/v1", "ranking_applied": True,
        }))

    def test_missing_false_and_non_boolean_ranking_are_not_claimed_as_applied(self):
        for receipt in (None, [], {}, {"ranking_applied": True},
                        {"schema": "basira-odvl-ranking/v1"},
                        *({"schema": "basira-odvl-ranking/v1", "ranking_applied": value}
                          for value in (False, None, 1, "true"))):
            with self.subTest(receipt=receipt):
                self.assertFalse(odvl_applied(receipt))

    def test_observation_is_never_counted_as_a_ranking(self):
        self.assertFalse(odvl_applied({
            "schema": "basira-odvl-observation/v1", "available": True,
        }))
        self.assertFalse(odvl_applied({
            "schema": "basira-odvl-observation/v1", "available": True,
            "ranking_applied": True,
        }))


if __name__ == "__main__":
    unittest.main()
