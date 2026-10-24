"""Authentification du témoin : clés temporaires, aucun service ni réseau."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "invite/agent_labo"))
import jetons
import service_temoin


class JetonsTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name, value in (("CLE", self.root / "key"), ("ETAT", self.root / "state"),
                            ("ROOT_UID", os.geteuid())):
            p = patch.object(jetons, name, value)
            p.start()
            self.addCleanup(p.stop)
        jetons.initialiser()

    def test_signature_requise_meme_avec_version_publique(self):
        for token in (None, "v1", "v1.forbidden", "v999.forbidden",
                      "v1." + "0" * 32 + "." + "0" * 64):
            self.assertFalse(service_temoin.jeton_valide(token)[0])
        token = jetons.emettre()
        self.assertTrue(service_temoin.jeton_valide(token)[0])
        self.assertFalse(jetons.verifier(token[:-1] + ("a" if token[-1] != "a" else "b")))

    def test_rotation_refuse_anciens_jetons_et_accepte_nouveau(self):
        old = jetons.emettre()
        self.assertEqual(jetons.tourner(), 2)
        self.assertFalse(jetons.verifier(old))
        self.assertFalse(jetons.verifier(jetons.emettre(1)))
        self.assertTrue(jetons.verifier(jetons.emettre()))

    def test_cle_absente_insecure_ou_symbolique_refusee(self):
        token = jetons.emettre()
        jetons.CLE.chmod(0o644)
        self.assertFalse(jetons.verifier(token))
        jetons.CLE.chmod(0o600)
        original = self.root / "original"
        jetons.CLE.rename(original)
        jetons.CLE.symlink_to(original)
        self.assertFalse(jetons.verifier(token))
        jetons.CLE.unlink()
        self.assertFalse(jetons.verifier(token))

    def test_etat_absent_ne_retourne_pas_a_la_version_un(self):
        token = jetons.emettre()
        jetons.ETAT.unlink()
        self.assertFalse(jetons.verifier(token))


if __name__ == "__main__":
    unittest.main()
