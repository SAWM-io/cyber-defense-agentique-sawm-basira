"""Fraîcheur : transitions, annonces et réserves, sans réseau ni navigateur.

Le seul processus enfant est Node sur stdin, autorisé par tests/run_safe.py.
La géométrie réelle reste à vérifier dans le parcours navigateur CUA.
"""
from html.parser import HTMLParser
import json
import pathlib
import re
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HTML = ROOT / "controleur/tableau.html"


class StatutParser(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.zone = None
        self.spans = []
        self.current = None
        markup = '<div id="avert"' + source.split('<div id="avert"', 1)[1].split('</div>', 1)[0] + '</div>'
        self.feed(markup)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "div":
            self.zone = attrs
        elif tag == "span":
            self.current = {"attrs": attrs, "text": ""}
            self.spans.append(self.current)

    def handle_endtag(self, tag):
        if tag == "span":
            self.current = None

    def handle_data(self, value):
        if self.current is not None:
            self.current["text"] += value


class FraicheurDashboardTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node requis pour les transitions DOM")
    def test_transitions_preserve_status_nodes_and_do_not_claim_unconfirmed_health(self):
        source = HTML.read_text()
        markup = StatutParser(source)
        messages = {span["attrs"]["data-message"]: span["text"] for span in markup.spans
                    if "data-message" in span["attrs"]}
        initial = next(span["text"] for span in markup.spans if span["attrs"].get("id") == "avert-message")
        helpers = "function texte" + source.split("function texte", 1)[1].split("function etat", 1)[0]
        freshness = "function afficherStatutCollecte" + source.split("function afficherStatutCollecte", 1)[1].split("function preuves", 1)[0]
        script = r'''
const assert = require('node:assert/strict');
const messages = MESSAGES;
class Element {
  constructor(value = '') { this._text = value; this.writes = 0; this.className = ''; this.value = '1000'; }
  get textContent() { return this._text; }
  set textContent(value) { this._text = value; this.writes++; }
}
const zone = {dataset: {etat: 'attente'}, get hidden() { return false; },
  set hidden(_) { throw Error('Le statut ne doit pas quitter le flux'); },
  set textContent(_) { throw Error('Ne pas supprimer les messages réservés'); }};
const message = new Element(INITIAL);
const nodes = new Map([['#avert', zone], ['#avert-message', message]]);
for (const [state, text] of Object.entries(messages)) {
  nodes.set('#avert [data-message="' + state + '"]', new Element(text));
}
const $ = selector => {
  if (!nodes.has(selector)) nodes.set(selector, new Element());
  return nodes.get(selector);
};
const fini = value => typeof value === 'number' && Number.isFinite(value);
const fmt = value => fini(value) ? String(value) : 'N/D';
const afficherAlertes = () => {}, afficherActiviteAgent = () => {}, afficherEtatEmotionnel = () => {};
let maintenant = 100000, donnees = null, dernierSucces = maintenant, echecCollecteur = false;
Date.now = () => maintenant;
const fresh = () => ({telemetrie_invite: {age_ms: 10, connectee: true}});
function check(expected, text) {
  fraicheur();
  assert.equal(zone.dataset.etat, expected);
  assert.ok(message.textContent.includes(text), `Message incorrect pour ${expected}`);
  assert.equal(message.textContent, messages[expected]);
  assert.equal($('#avert-message'), message); // Le même nœud live reste en place.
  assert.equal(zone.hidden, false);
}
'''.replace("MESSAGES", json.dumps(messages)).replace("INITIAL", json.dumps(initial))
        checks = r'''
check('attente', 'aucune mesure reçue');
donnees = fresh();
check('recent', 'Télémétrie récente');
assert.equal($('#lien').className, 'jeton etat-ok');
const writes = message.writes;
for (let i = 0; i < 5; i++) fraicheur();
assert.equal(message.writes, writes, 'Un état inchangé ne doit pas être réannoncé');
maintenant += 2490; // Âge total = 2,5 s : avertissement immédiat, sans délai ajouté.
check('invite', 'état actuel non confirmé');
assert.equal($('#lien').className, 'jeton etat-ko');
maintenant += 1011;
check('collecteur', 'mesures conservées');
dernierSucces = maintenant;
check('recent', 'Télémétrie récente');
echecCollecteur = true;
check('collecteur', 'état actuel non confirmé');
assert.equal($('#lien').className, 'jeton etat-ko');
echecCollecteur = false;
donnees.telemetrie_invite.connectee = false;
check('invite', 'absente ou périmée');
assert.equal($('#lien').className, 'jeton etat-ko');
for (const age of [-10, null, NaN, Infinity]) {
  donnees.telemetrie_invite = {age_ms: age, connectee: true};
  check('invite', 'état actuel non confirmé');
  assert.equal($('#lien').className, 'jeton etat-ko');
}
donnees = null; echecCollecteur = true;
check('absent', 'aucune mesure disponible');
donnees = fresh(); echecCollecteur = false;
check('recent', 'Télémétrie récente');
dernierSucces = maintenant + 1; // Une horloge incohérente ne confirme pas une liaison.
check('collecteur', 'état actuel non confirmé');
assert.equal($('#lien').className, 'jeton etat-ko');
'''
        result = subprocess.run([shutil.which("node"), "-"], input=script + helpers + freshness + checks,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_messages_have_accessibility_hidden_reserves_in_the_same_grid_cell(self):
        source = HTML.read_text()
        markup = StatutParser(source)
        self.assertEqual(markup.zone["role"], "status")
        self.assertEqual(markup.zone["aria-atomic"], "true")
        self.assertNotIn("hidden", markup.zone)
        states = set()
        for span in markup.spans:
            attrs = span["attrs"]
            if "data-message" not in attrs:
                self.assertEqual(attrs["id"], "avert-message")
                self.assertNotIn("aria-hidden", attrs)
                continue
            states.add(attrs["data-message"])
            self.assertEqual(attrs["aria-hidden"], "true")
            self.assertIn("avert-reserve", attrs["class"].split())
            self.assertTrue(span["text"].strip())
        self.assertEqual(states, {"attente", "recent", "invite", "collecteur", "absent"})
        rules = {}
        for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", source.split("<style>", 1)[1].split("</style>", 1)[0]):
            selector = selector.strip()
            rules[selector] = rules.get(selector, "") + body
        self.assertRegex(rules["#avert"], r"display:\s*grid")
        self.assertRegex(rules["#avert > span"], r"grid-area:\s*1\s*/\s*1")
        reserve = next(body for selector, body in rules.items() if selector.endswith("#avert .avert-reserve"))
        self.assertRegex(reserve, r"visibility:\s*hidden")
        self.assertNotRegex(reserve, r"display:\s*none")


if __name__ == "__main__":
    unittest.main()
