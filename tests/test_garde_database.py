"""Garde de disponibilité : mandat et attribution indispensables, aucun runtime."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controleur.garde_database import proposer

UNIT = "labo-db-guard.service"


def mesures():
    return (
        {"database_policy": {"unit": UNIT, "availability_required": True,
                             "exclusive_lock_authorized": False},
         "unites_autorisees": [UNIT], "unites_protegees": ["labo-temoin.service"],
         "veille": {"actions_automatiques": ["arreter-service"]}},
        {"read_available": True, "write_available": True},
        {"read_available": False, "write_available": False,
         "errors": {"read": "SQLITE_BUSY", "write": "SQLITE_BUSY"}},
        {"unit": UNIT, "attribution_available": True, "fd_on_database": True,
         "kernel_locks": ["7: POSIX ADVISORY WRITE 42 08:01:1234 0 EOF"],
         "systemd": {"ActiveState": "active"}},
    )


class GardeDatabaseTest(unittest.TestCase):
    def test_violation_disponibilite_attribuee_propose_arret_exact_sans_mutation(self):
        args = mesures()
        original = copy.deepcopy(args)
        proposition = proposer(*args)
        self.assertIsNotNone(proposition)
        self.assertEqual(proposition.action, "arreter-service")
        self.assertEqual(proposition.cible, UNIT)
        self.assertIn("Garde local", proposition.justification)
        self.assertEqual(args, original)

    def test_verrou_autorise_ou_absence_de_delegation_ne_propose_aucun_arret(self):
        for condition in ("verrou_autorise", "disponibilite_facultative", "action_non_deleguee",
                          "politique_absente", "cible_hors_manifeste", "cible_protegee"):
            manifest, baseline, current, attribution = mesures()
            if condition == "verrou_autorise":
                manifest["database_policy"]["exclusive_lock_authorized"] = True
            elif condition == "disponibilite_facultative":
                manifest["database_policy"]["availability_required"] = False
            elif condition == "action_non_deleguee":
                manifest["veille"]["actions_automatiques"] = ["limiter-cpu"]
            elif condition == "politique_absente":
                del manifest["database_policy"]
            elif condition == "cible_hors_manifeste":
                manifest["unites_autorisees"] = ["labo-autre.service"]
            else:
                manifest["unites_protegees"].append(UNIT)
            with self.subTest(condition=condition):
                self.assertIsNone(proposer(manifest, baseline, current, attribution))

    def test_booleens_malformes_ne_deviennent_jamais_autorisations_ou_mesures(self):
        for target, field in (("policy", "availability_required"),
                              ("policy", "exclusive_lock_authorized"),
                              ("baseline", "read_available"), ("baseline", "write_available"),
                              ("current", "read_available"), ("current", "write_available"),
                              ("attribution", "attribution_available"),
                              ("attribution", "fd_on_database")):
            for value in (None, 0, 1, "true", "false", [], {}):
                manifest, baseline, current, attribution = mesures()
                blocks = {"policy": manifest["database_policy"], "baseline": baseline,
                          "current": current, "attribution": attribution}
                blocks[target][field] = value
                with self.subTest(target=target, field=field, value=value):
                    self.assertIsNone(proposer(manifest, baseline, current, attribution))

    def test_attribution_incomplete_divergente_ou_obsolete_ne_permet_pas_arret(self):
        for changed in ({"unit": "labo-autre.service"}, {"unit": None},
                        {"attribution_available": False}, {"fd_on_database": False},
                        {"kernel_locks": []}, {"kernel_locks": None},
                        {"systemd": {}}, {"systemd": {"ActiveState": "inactive"}}):
            manifest, baseline, current, attribution = mesures()
            with self.subTest(changed=changed):
                self.assertIsNone(proposer(manifest, baseline, current, {**attribution, **changed}))

    def test_hash_different_et_erreurs_non_attribuables_ne_suffisent_pas(self):
        for current in (
            {"read_available": True, "write_available": True, "reference_matches": False},
            {"read_available": False, "write_available": False,
             "errors": {"read": "SQLITE_CORRUPT", "write": "SQLITE_CORRUPT"}},
            {"read_available": False, "write_available": False, "errors": {}},
            {"read_available": True, "write_available": False,
             "errors": {"read": "SQLITE_BUSY", "write": "SQLITE_BUSY"}},
        ):
            manifest, baseline, _, attribution = mesures()
            with self.subTest(current=current):
                self.assertIsNone(proposer(manifest, baseline, current, attribution))

    def test_aucun_arret_si_la_base_etait_deja_indisponible(self):
        for field in ("read_available", "write_available"):
            manifest, baseline, current, attribution = mesures()
            baseline[field] = False
            with self.subTest(field=field):
                self.assertIsNone(proposer(manifest, baseline, current, attribution))


if __name__ == "__main__":
    unittest.main()
