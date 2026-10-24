"""Reprise : une étape non mesurée doit ARRÊTER la procédure, pas la décorer.

Ces tests visent les façons de conclure faux, pas la couverture de lignes :
une comparaison tautologique, une preuve que l'invité pourrait fabriquer, un
isolement annoncé mais non constaté, une révocation sans effet, une barrière
d'étapes contournée.
"""
import hashlib
import json
from pathlib import Path
import contextlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from controleur import reprise                                  # noqa: E402
from controleur.recovery_contract import (                      # noqa: E402
    ControllerEvidence, RecoveryBinding, RecoveryContractError, RecoveryState,
    Ed25519PrivateKey, key_fingerprint, sign_manifest,
)


def _binding(tmp, empreinte="a" * 64):
    cle = Ed25519PrivateKey.generate()
    return cle, RecoveryBinding(
        run_id="essai-1", vm_id=reprise.VM_UUID, target=str(tmp / "cible.utm"),
        clean_image_sha256=empreinte,
        institutional_key_fingerprint=key_fingerprint(cle.public_key()),
    )


class ApprobationTest(unittest.TestCase):
    """L'empreinte approuvée vient d'AVANT l'incident, sinon on ne prouve rien."""

    def test_sans_approbation_la_procedure_refuse_de_demarrer(self):
        with tempfile.TemporaryDirectory() as d:
            reference = Path(d) / "reference.img"
            reference.write_bytes(b"image de reference")
            absente = Path(d) / "jamais-approuvee.sha256"
            with mock.patch.object(reprise, "REFERENCE_BOX", reference), \
                 mock.patch.object(reprise, "APPROBATION", absente):
                with self.assertRaises(reprise.RepriseErreur) as ctx:
                    reprise.conduire(run_id="essai-2", appliquer=False,
                                     jusqu_a="proof")
        self.assertIn("approuvée", str(ctx.exception))

    def test_empreinte_approuvee_malformee_refusee(self):
        for mauvaise in ("", "zz" * 32, "abc"):
            with self.subTest(mauvaise=mauvaise):
                with self.assertRaises(reprise.RepriseErreur):
                    reprise._digest_valide(mauvaise)

    def test_reference_differente_de_l_approbation_arrete_la_reprise(self):
        """Le cas qui compte : la référence a été remplacée depuis l'approbation."""
        with tempfile.TemporaryDirectory() as d:
            reference = Path(d) / "reference.img"
            reference.write_bytes(b"une image REMPLACEE depuis l'approbation")
            approuvee = hashlib.sha256(b"l'image d'origine").hexdigest()
            _, binding = _binding(Path(d), empreinte=approuvee)
            with mock.patch.object(reprise, "REFERENCE_BOX", reference):
                with self.assertRaises(reprise.RepriseErreur) as ctx:
                    reprise.etape_reference(binding)
        self.assertIn("ne correspond pas", str(ctx.exception))


class IsolementTest(unittest.TestCase):
    """L'isolement se CONSTATE ; et ces tests doivent pouvoir échouer.

    La version précédente de ce fichier contenait un test qui ASSERTAIT la
    réussite de l'étape avec `isolated_on_dans_qemu` faux — il verrouillait
    le défaut au lieu de le révéler. Il est renversé ici.
    """

    def _patches(self, sondage, ligne, config):
        return (mock.patch.object(reprise, "adresses_de_la_cible",
                                  return_value=["192.0.2.3"]),
                mock.patch.object(reprise, "sonder_cible", return_value=sondage),
                mock.patch.object(reprise, "ligne_qemu", return_value=ligne),
                mock.patch.object(reprise, "config_vm", return_value=config))

    @staticmethod
    def _config(isole):
        return {"Network": [{"Mode": "Host", "IsolateFromHost": isole}],
                "Sharing": {}, "Drive": []}

    def test_cible_encore_joignable_arrete_la_procedure(self):
        _, binding = _binding(Path("/tmp"))
        vivante = {"192.0.2.3": {"icmp": True, "tcp22": True}}
        with contextlib.ExitStack() as pile:
            for c in self._patches(vivante, "… isolated=on …", self._config(True)):
                pile.enter_context(c)
            with self.assertRaises(reprise.RepriseErreur) as ctx:
                reprise.etape_isolement(binding, appliquer=False, fenetre_s=0,
                                        sondes=1)
        self.assertIn("répond encore", str(ctx.exception))

    def test_service_arrete_mais_reseau_ouvert_NE_PASSE_PAS(self):
        """Le défaut central trouvé par la vérification adverse.

        Port 22 fermé mais ICMP qui répond : un service applicatif arrêté ne
        doit jamais être pris pour un lien réseau coupé.
        """
        _, binding = _binding(Path("/tmp"))
        sshd_mort = {"192.0.2.3": {"icmp": True, "tcp22": False}}
        with contextlib.ExitStack() as pile:
            for c in self._patches(sshd_mort, "… isolated=on …", self._config(True)):
                pile.enter_context(c)
            with self.assertRaises(reprise.RepriseErreur) as ctx:
                reprise.etape_isolement(binding, appliquer=False, fenetre_s=0,
                                        sondes=1)
        self.assertIn("répond encore", str(ctx.exception))

    def test_un_peripherique_reseau_subsistant_fait_ECHOUER(self):
        """Le critère corrigé : ce n'est pas `isolated=on`, c'est l'absence de réseau.

        Mesuré le 2026-09-22 : avec `isolated=on` correctement appliqué, la
        cible répondait encore en ICMP et en TCP sur ses deux familles
        d'adresses. Cet indicateur isole les VM entre elles, pas de leur hôte.
        """
        _, binding = _binding(Path("/tmp"))
        muette = {"192.0.2.3": {"icmp": False, "tcp22": False}}
        avec_reseau = ("qemu … -netdev vmnet-host,id=net0,isolated=on …")
        with contextlib.ExitStack() as pile:
            for c in self._patches(muette, avec_reseau, self._config(True)):
                pile.enter_context(c)
            with self.assertRaises(reprise.RepriseErreur) as ctx:
                reprise.etape_isolement(binding, appliquer=False, fenetre_s=0,
                                        sondes=1)
        self.assertIn("périphérique réseau subsiste", str(ctx.exception))

    def test_cible_muette_et_sans_reseau_PASSE(self):
        """Et le cas nominal doit passer, sinon la garde est inutilisable."""
        _, binding = _binding(Path("/tmp"))
        muette = {"192.0.2.3": {"icmp": False, "tcp22": False}}
        vivante = {"192.0.2.3": {"icmp": True, "tcp22": True}}
        sans_reseau = "qemu-aarch64-softmmu -nographic -uuid … -device virtio-rng-pci"
        with contextlib.ExitStack() as pile:
            pile.enter_context(mock.patch.object(reprise, "adresses_de_la_cible",
                                                 return_value=["192.0.2.3"]))
            pile.enter_context(mock.patch.object(reprise, "sonder_cible",
                                                 side_effect=[vivante, muette]))
            pile.enter_context(mock.patch.object(reprise, "ligne_qemu",
                                                 return_value=sans_reseau))
            pile.enter_context(mock.patch.object(reprise, "config_vm",
                                                 return_value=self._config(True)))
            m = reprise.etape_isolement(binding, appliquer=False, fenetre_s=0,
                                        sondes=1)
        self.assertTrue(m["aucun_peripherique_reseau"])
        self.assertTrue(m["silencieuse_sur_toute_la_fenetre"])
        self.assertEqual(m["motifs_echec"], [])

    def test_processus_qemu_non_identifie_arrete_l_etape(self):
        """ligne_qemu() rend None si ce n'est pas exactement un processus."""
        _, binding = _binding(Path("/tmp"))
        muette = {"192.0.2.3": {"icmp": False, "tcp22": False}}
        with contextlib.ExitStack() as pile:
            for c in self._patches(muette, None, self._config(True)):
                pile.enter_context(c)
            with self.assertRaises(reprise.RepriseErreur):
                reprise.etape_isolement(binding, appliquer=False, fenetre_s=0,
                                        sondes=1)

    def test_isolated_on_seul_ne_suffit_PAS(self):
        """Le défaut de conception trouvé : l'indicateur ne prouve rien.

        Cible muette mais périphérique réseau présent avec `isolated=on` :
        l'étape doit refuser, car ce silence peut venir d'autre chose.
        """
        _, binding = _binding(Path("/tmp"))
        muette = {"192.0.2.3": {"icmp": False, "tcp22": False}}
        with contextlib.ExitStack() as pile:
            for c in self._patches(muette, "-netdev vmnet-host,isolated=on",
                                   self._config(True)):
                pile.enter_context(c)
            with self.assertRaises(reprise.RepriseErreur):
                reprise.etape_isolement(binding, appliquer=False, fenetre_s=0,
                                        sondes=1)


class RevocationTest(unittest.TestCase):
    """Révoquer, c'est faire tourner — pas supprimer une ligne."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        coffre = mock.patch.object(reprise, "COFFRE", Path(tmp.name))
        coffre.start()
        self.addCleanup(coffre.stop)
        runtime = mock.patch.object(reprise, "_run", side_effect=AssertionError(
            "Un test unitaire ne doit jamais appeler le runtime réel"))
        runtime.start()
        self.addCleanup(runtime.stop)

    def test_aucune_revocation_reelle_arrete_la_procedure(self):
        _, binding = _binding(Path("/tmp"))
        with mock.patch.object(reprise, "_revoquer_acces",
                               return_value=[{"accès": "x", "revoque": False}]):
            with self.assertRaises(reprise.RepriseErreur) as ctx:
                reprise.etape_reconstruction(binding, appliquer=False)
        self.assertIn("aucun accès", str(ctx.exception))

    def test_le_drapeau_revoque_ne_vient_jamais_du_mode_d_execution(self):
        """Le défaut le plus grave trouvé : `revoque = bool(appliquer)`.

        Sans post-condition mesurée, aucun accès ne peut être déclaré révoqué.
        """
        with mock.patch.object(reprise, "_jeton", return_value="illisible"):
            sorties = reprise._revoquer_acces(appliquer=True, adresse="203.0.113.1")
        for x in sorties:
            with self.subTest(acces=x["accès"]):
                self.assertFalse(x["revoque"],
                                 "une révocation non prouvée ne doit jamais "
                                 "être comptée")

    def test_la_mesure_seule_ne_revogue_pas_les_jetons(self):
        sorties = reprise._revoquer_acces(appliquer=False)
        jeton = next(x for x in sorties if "jetons" in x["accès"])
        self.assertFalse(jeton["revoque"])
        self.assertIsNone(jeton["post_condition"]["ancien_jeton_rejoue"])

    def test_la_cle_cloud_est_annoncee_comme_NON_revoquee(self):
        """Elle ne l'est pas par ce module : le dire est le minimum honnête."""
        sorties = reprise._revoquer_acces(appliquer=False)
        cloud = next(x for x in sorties if "Cloud" in x["accès"])
        self.assertFalse(cloud["revoque"])
        self.assertIn("reste_a_faire", cloud)

    def test_empreinte_apres_rotation_vise_la_cle_promue(self):
        for nom, contenu in (("cle_labo", "ancienne-privee-fictive"),
                             ("cle_labo.pub", "ancienne-publique-fictive"),
                             ("cle_labo.neuve", "nouvelle-privee-fictive"),
                             ("cle_labo.neuve.pub", "nouvelle-publique-fictive")):
            (reprise.COFFRE / nom).write_text(contenu)
        def empreinte(path):
            return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        with mock.patch.object(reprise, "_empreinte_cle_publique", side_effect=empreinte), \
                mock.patch.object(reprise, "_ssh", side_effect=[
                    (0, "POSE", ""), (255, "", "refus"), (0, "", "")]), \
                mock.patch.object(reprise, "_jeton", return_value="illisible"):
            sorties = reprise._revoquer_acces(appliquer=True)
        cle = sorties[0]
        self.assertTrue(cle["revoque"])
        self.assertTrue(cle["post_condition"]["promue_en_cle_administration"])
        self.assertEqual(cle["empreinte_apres"], empreinte(reprise.COFFRE / "cle_labo.pub"))
        self.assertNotEqual(cle["empreinte_avant"], cle["empreinte_apres"])
        self.assertIsNotNone(cle["empreinte_apres"])
        self.assertFalse((reprise.COFFRE / "cle_labo.neuve.pub").exists())


class VerificationTest(unittest.TestCase):
    """La remise en état se vérifie ; un contrôle raté doit ARRÊTER."""

    def test_disque_prepare_sans_instance_ne_permet_aucune_verification(self):
        _, binding = _binding(Path("/tmp"))
        for flags in ({}, {"instance_creee": True},
                      {"reconstruction_effective": True},
                      {"instance_creee": 1, "reconstruction_effective": True}):
            with self.subTest(flags=flags), mock.patch.object(
                    reprise, "empreinte_fichier", side_effect=AssertionError("pas de mesure")):
                with self.assertRaises(reprise.RepriseErreur):
                    reprise.etape_verification(binding, {"rebuilt": {"reconstruction": flags}})

    def test_remise_en_service_exige_instance_et_verification(self):
        _, binding = _binding(Path("/tmp"))
        for mesures in ({}, {"verified": {"tous_concluants": True}},
                        {"rebuilt": {"reconstruction": {
                            "instance_creee": True, "reconstruction_effective": True}}}):
            with self.subTest(mesures=mesures), mock.patch.object(
                    reprise, "_run", side_effect=AssertionError("aucune mutation")):
                with self.assertRaises(reprise.RepriseErreur):
                    reprise.etape_remise_en_service(binding, mesures)

    def test_disque_suspect_absent_fait_echouer_la_verification(self):
        _, binding = _binding(Path("/tmp"))
        mesures = {"rebuilt": {"reconstruction": {
            "disque_reconstruit": None, "disque_preuve": "/introuvable/x.qcow2"}}}
        with self.assertRaises(reprise.RepriseErreur) as ctx:
            reprise.etape_verification(binding, mesures)
        self.assertIn("non vérifiée", str(ctx.exception))


class BarriereTest(unittest.TestCase):
    """La barrière du contrat doit tenir, y compris face à notre propre code."""

    def test_un_plan_non_applique_ne_devient_jamais_released(self):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as stack:
            root = Path(d)
            reference = root / "reference.img"
            reference.write_bytes(b"fixture")
            approval = root / "approval"
            approval.write_text(hashlib.sha256(b"fixture").hexdigest())
            key = Ed25519PrivateKey.generate()
            for name, value in (("REFERENCE_BOX", reference), ("APPROBATION", approval),
                                ("PREUVES", root / "preuves")):
                stack.enter_context(mock.patch.object(reprise, name, value))
            stack.enter_context(mock.patch.object(reprise, "_empreinte_signataire",
                                                 return_value=key_fingerprint(key.public_key())))
            stack.enter_context(mock.patch.object(reprise, "_run",
                                                 side_effect=AssertionError("aucune mutation")))
            for name in ("etape_preuve", "etape_isolement", "etape_reference"):
                stack.enter_context(mock.patch.object(reprise, name, return_value={}))
            stack.enter_context(mock.patch.object(reprise, "etape_reconstruction", return_value={
                "reconstruction": {"instance_creee": True, "reconstruction_effective": True}}))
            stack.enter_context(mock.patch.object(reprise, "etape_verification", return_value={
                "tous_concluants": True}))
            def signer(binding, proof):
                return sign_manifest(binding, private_key=key, proof=proof), key.public_key()
            original = reprise.RecoveryState.advance
            advanced = []
            def track(state, stage, **kwargs):
                advanced.append(stage)
                return original(state, stage, **kwargs)
            stack.enter_context(mock.patch.object(reprise.RecoveryState, "advance", new=track))
            with self.assertRaisesRegex(reprise.RepriseErreur, "non effectuée"):
                reprise.conduire(run_id="plan-seulement", appliquer=False, signer=signer)
            self.assertIn("verified", advanced)
            self.assertNotIn("released", advanced)

    def test_impossible_de_sauter_une_etape(self):
        cle, binding = _binding(Path("/tmp"))
        preuve = ControllerEvidence(stage="proof", run_id=binding.run_id,
                                    vm_id=binding.vm_id, target=binding.target,
                                    sha256="d" * 64, origin="host-controller",
                                    passed=True)
        etat = RecoveryState(binding, preuve)
        suivante = ControllerEvidence(stage="rebuilt", run_id=binding.run_id,
                                      vm_id=binding.vm_id, target=binding.target,
                                      sha256="e" * 64, origin="host-controller",
                                      passed=True)
        with self.assertRaises(RecoveryContractError):
            etat.advance("rebuilt", evidence=suivante)

    def test_verification_de_reference_exige_un_manifeste_signe(self):
        """Sans manifeste signé, « référence vérifiée » ne veut rien dire."""
        cle, binding = _binding(Path("/tmp"))
        preuve = ControllerEvidence(stage="proof", run_id=binding.run_id,
                                    vm_id=binding.vm_id, target=binding.target,
                                    sha256="f" * 64, origin="host-controller",
                                    passed=True)
        etat = RecoveryState(binding, preuve)
        isole = ControllerEvidence(stage="isolated", run_id=binding.run_id,
                                   vm_id=binding.vm_id, target=binding.target,
                                   sha256="1" * 64, origin="host-controller",
                                   passed=True)
        etat.advance("isolated", evidence=isole)
        bidon = ControllerEvidence(stage="recovery_verified", run_id=binding.run_id,
                                   vm_id=binding.vm_id, target=binding.target,
                                   sha256="2" * 64, origin="host-controller",
                                   passed=True)
        with self.assertRaises(RecoveryContractError):
            etat.advance("recovery_verified", evidence=bidon)
        manifeste = sign_manifest(binding, private_key=cle, proof=preuve)
        self.assertEqual(etat.advance("recovery_verified", manifest=manifeste,
                                      public_key=cle.public_key()),
                         "recovery_verified")

    def test_le_module_n_ecrit_plus_directement_dans_l_historique(self):
        source = (Path(__file__).resolve().parents[1]
                  / "controleur" / "reprise.py").read_text()
        self.assertNotIn("_history.append", source,
                         "la barrière du contrat ne doit jamais être contournée")


class SceauTest(unittest.TestCase):
    """Une preuve scellée doit être vérifiable après coup, hors de l'invité."""

    def test_le_sceau_couvre_bien_la_mesure(self):
        mesure = {"b": 2, "a": 1}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(reprise, "PREUVES", Path(d)):
            chemin, empreinte = reprise._sceller("essai-sceau", "proof", mesure)
            octets = chemin.read_bytes()
        self.assertEqual(hashlib.sha256(octets).hexdigest(), empreinte)
        self.assertEqual(json.loads(octets), mesure)


if __name__ == "__main__":
    unittest.main()
