#!/bin/bash
# Bascule du profil reseau de la VM de laboratoire, avec preuve.
#
#   reseau.sh ouvrir   : phase d'INSTALLATION declaree — vmnet-shared, WAN.
#   reseau.sh fermer   : phase d'ESSAI — vmnet-host + isolated=on, aucune sortie.
#   reseau.sh etat     : ce que QEMU applique REELLEMENT (pas ce qu'on croit).
#
# La regle du mandat : une sortie temporaire pour installer des dependances est
# distincte de la phase d'essai et doit etre refermee ensuite. Chaque bascule
# est horodatee dans releves/journal-reseau.txt : on doit pouvoir montrer au
# client quand la VM a eu une sortie et quand elle ne l'avait plus.
set -euo pipefail

VM_UUID="${SAWM_LABO_VM_UUID:?Set SAWM_LABO_VM_UUID to the dedicated test VM UUID}"
VM_NOM="${SAWM_LABO_VM_NOM:?Set SAWM_LABO_VM_NOM to the dedicated test VM name}"
BUNDLE="$HOME/Library/Containers/com.utmapp.UTM/Data/Documents/${VM_NOM}.utm"
PLIST="$BUNDLE/config.plist"
ICI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOURNAL="$ICI/../releves/journal-reseau.txt"

horodate() { date -u +%Y-%m-%dT%H:%M:%SZ; }

attendre_arret() {
  utmctl stop "$VM_UUID" >/dev/null 2>&1 || true
  for _ in $(seq 1 40); do
    [ "$(utmctl status "$VM_UUID" 2>/dev/null)" = "stopped" ] && return 0
    sleep 2
  done
  echo "la VM ne s'arrete pas proprement" >&2; return 1
}

attendre_agent() {
  # L'agent invite est le canal de controle : sans lui on ne sait rien.
  for _ in $(seq 1 45); do
    if utmctl exec "$VM_UUID" --cmd /bin/true >/dev/null 2>&1; then return 0; fi
    sleep 3
  done
  echo "agent invite injoignable apres demarrage" >&2; return 1
}

appliquer() {
  local mode="$1" isole="$2" libelle="$3"
  [ "${SAWM_LABO_ALLOW_NETWORK_CHANGE:-0}" = "1" ] || { echo "Set SAWM_LABO_ALLOW_NETWORK_CHANGE=1 for this explicit lab-only mutation" >&2; return 2; }
  attendre_arret
  osascript -e 'tell application "UTM" to quit' >/dev/null 2>&1 || true
  sleep 3
  plutil -replace Network.0.Mode -string "$mode" "$PLIST"
  plutil -replace Network.0.IsolateFromHost -bool "$isole" "$PLIST"
  utmctl start "$VM_UUID" >/dev/null 2>&1
  attendre_agent
  printf '%s  %-12s  Mode=%s IsolateFromHost=%s\n' "$(horodate)" "$libelle" "$mode" "$isole" >> "$JOURNAL"
  etat
}

etat() {
  echo "--- configuration declaree ---"
  plutil -extract Network.0 json -o - "$PLIST"; echo
  echo "--- ce que QEMU applique reellement ---"
  local pid
  pid="$(pgrep -f qemu-aarch64-softmmu | head -1 || true)"
  if [ -n "$pid" ]; then
    ps -o command= -p "$pid" | tr ' ' '\n' | grep -E '^vmnet-|isolated' || echo "(aucun netdev vmnet trouve)"
  else
    echo "(QEMU n'est pas en cours d'execution)"
  fi
}

case "${1:-etat}" in
  ouvrir) appliquer Shared NO  "INSTALLATION" ;;
  fermer) appliquer Host   YES "ESSAI" ;;
  etat)   etat ;;
  *) echo "usage: $0 {ouvrir|fermer|etat}" >&2; exit 2 ;;
esac
