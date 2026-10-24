"""Une instance parallèle (VM neuve, tableau de bord et projet Basira distincts) se configure par variables
d'environnement, avec des valeurs par défaut sûres sans cible privée implicite."""
import importlib
import os

import pytest


def _recharge(nom):
    mod = importlib.import_module(nom)
    return importlib.reload(mod)


def test_defauts_locaux_sans_cible_implicite(monkeypatch):
    for v in ("SAWM_LABO_VM_UUID", "LABO_PORT_TELEMETRIE", "LABO_HTTP", "SAWM_LABO_SSH_CIBLE", "LABO_AUTH_BIND", "LABO_BIND", "SAWM_LABO_LOCAL_VM"):
        monkeypatch.delenv(v, raising=False)
    col = _recharge("controleur.collecteur")
    assert col.VM_UUID == "00000000-0000-0000-0000-000000000000"
    assert col.adresse_telemetrie({}) == ("127.0.0.1", 47900)
    assert col.ECOUTE_HTTP == ("127.0.0.1", 8899)
    veille = _recharge("controleur.veille")
    assert veille.URL_PORT == 8899
    vm = _recharge("controleur.vm_labo")
    assert vm.SSH[-1] == ""
    guard = _recharge("invite.agent_labo.auth_guard")
    assert guard.HOST == "127.0.0.1"


def test_surcharges_isolent_une_seconde_instance(monkeypatch):
    monkeypatch.setenv("SAWM_LABO_VM_UUID", "11111111-2222-3333-4444-555566667777")
    monkeypatch.setenv("LABO_PORT_TELEMETRIE", "47901")
    monkeypatch.setenv("LABO_HTTP", "8898")
    monkeypatch.setenv("SAWM_LABO_SSH_CIBLE", "vagrant@192.0.2.50")
    monkeypatch.setenv("LABO_AUTH_BIND", "192.0.2.50")
    col = _recharge("controleur.collecteur")
    assert col.VM_UUID == "11111111-2222-3333-4444-555566667777"
    assert col.adresse_telemetrie() == ("127.0.0.1", 47901)
    assert col.ECOUTE_HTTP == ("127.0.0.1", 8898)
    veille = _recharge("controleur.veille")
    assert veille.URL_PORT == 8898
    vm = _recharge("controleur.vm_labo")
    assert vm.SSH[-1] == "vagrant@192.0.2.50"
    assert any("known_hosts" in a for a in vm.SSH)
    guard = _recharge("invite.agent_labo.auth_guard")
    assert guard.HOST == "192.0.2.50"


def test_port_telemetrie_invalide_refuse_au_demarrage(monkeypatch):
    # Le port est lu au chargement du module (ECOUTE_TELEMETRIE) : un port hors limites échoue immédiatement.
    monkeypatch.setenv("LABO_PORT_TELEMETRIE", "70000")
    with pytest.raises(ValueError):
        _recharge("controleur.collecteur")
    monkeypatch.delenv("LABO_PORT_TELEMETRIE", raising=False)
    _recharge("controleur.collecteur")


def test_ssh_without_explicit_target_does_not_spawn(monkeypatch):
    monkeypatch.delenv("SAWM_LABO_SSH_CIBLE", raising=False)
    monkeypatch.delenv("SAWM_LABO_LOCAL_VM", raising=False)
    vm = _recharge("controleur.vm_labo")
    monkeypatch.setattr(vm.subprocess, "run", lambda *a, **k: pytest.fail("must not spawn without a target"))
    with pytest.raises(RuntimeError, match="explicitly"):
        vm.code("print('never sent')")
    assert "StrictHostKeyChecking=yes" in vm.SSH


@pytest.mark.parametrize("bind", ["0.0.0.0", "::", "8.8.8.8", "224.0.0.1", "localhost"])
def test_telemetry_rejects_wildcard_public_and_non_numeric_bind(bind):
    from controleur.collecteur import adresse_telemetrie
    with pytest.raises(ValueError):
        adresse_telemetrie({"LABO_BIND": bind})


def test_explicit_private_bind_remote_only():
    from controleur.collecteur import adresse_telemetrie
    assert adresse_telemetrie({"LABO_BIND": "10.23.45.1"}) == ("10.23.45.1", 47900)
    with pytest.raises(ValueError):
        adresse_telemetrie({"LABO_BIND": "10.23.45.1", "SAWM_LABO_LOCAL_VM": "1"})
