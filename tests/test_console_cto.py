"""Console : preuves admissibles et limites visibles, sans Cloud ni réseau."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controleur import console_cto as c


class ConsoleTest(unittest.TestCase):
    def pont(self, rows):
        pont = SimpleNamespace(entite="test", _client=Mock())
        pont.rappeler = Mock(return_value=SimpleNamespace(preuves=rows, moteur="test"))
        pont._client.respond.return_value = {"text": "Affirmation sans citation."}
        return pont

    def test_temps_absent_invalide_et_integrite_refusee_bloquent_le_modele(self):
        for fenetre in ("jour", "tout"):
            rows = [{"knowledge_time": t, "integrity_verified": True}
                    for t in (None, "invalide", True, float("nan"), float("inf"))]
            rows.append({"knowledge_time": "2026-09-23T12:00:00Z", "integrity_verified": False})
            pont = self.pont(rows)
            result = c.repondre(pont, question="Incidents ?", fenetre=fenetre)
            self.assertEqual(result["statut"], "sans_preuve")
            self.assertEqual(result["preuves_invalides"], len(rows))
            pont._client.respond.assert_not_called()

    def test_fenetre_et_absence_de_validation_des_citations_sont_explicites(self):
        pont = self.pont([
            {"evidence_id": "recent", "knowledge_time": 2000000000, "integrity_verified": True},
            {"evidence_id": "ancien", "knowledge_time": 1000000000, "integrity_verified": True}])
        with patch.object(c.time, "time", return_value=2000000001):
            result = c.repondre(pont, question="Incidents ?")
        self.assertEqual([p["evidence_id"] for p in result["preuves"]], ["recent"])
        self.assertEqual(result["preuves_hors_fenetre"], 1)
        self.assertEqual(result["validation_citations"], "non_fournie")
        self.assertIn("non fournie", result["avertissement_citations"])


if __name__ == "__main__":
    unittest.main()
