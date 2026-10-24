"""Recrée uniquement la table 8082 absente après démarrage de la VM.

Une table présente n'est jamais effacée ou réécrite. Si son périmètre diffère,
le service refuse de démarrer : aucune extension implicite aux autres ports.
"""
import json
import subprocess
from auth_guard import nft_scope_valid

# `create` échoue si la table est apparue depuis la lecture. Le fichier nft
# est une transaction : aucune règle n'est ajoutée à une table concurrente.
RULES = '''create table inet sawm_auth_guard
add set inet sawm_auth_guard blocked4 { type ipv4_addr; flags timeout; size 4096; }
add set inet sawm_auth_guard blocked6 { type ipv6_addr; flags timeout; size 4096; }
add chain inet sawm_auth_guard input { type filter hook input priority -5; policy accept; }
add rule inet sawm_auth_guard input tcp dport 8082 ip saddr @blocked4 counter drop
add rule inet sawm_auth_guard input tcp dport 8082 ip6 saddr @blocked6 counter drop
'''

def ensure(runner=subprocess.run):
    def read():
        p=runner(['/usr/sbin/nft','-j','list','ruleset'],capture_output=True,text=True,timeout=3)
        if p.returncode or len(p.stdout)>1024*1024:raise RuntimeError('firewall_inventory_failed')
        data=json.loads(p.stdout)
        entries=[row for row in data['nftables'] if any(
            isinstance(v,dict) and v.get('family')=='inet' and
            (v.get('name')=='sawm_auth_guard' if k=='table' else v.get('table')=='sawm_auth_guard')
            for k,v in row.items())]
        return entries
    existing=read()
    if not existing:
        runner(['/usr/sbin/nft','-f','-'],input=RULES,capture_output=True,text=True,timeout=3,check=True)
        existing=read()
    if not nft_scope_valid({'nftables':existing}):raise RuntimeError('firewall_scope_invalid')
    return True

if __name__=='__main__':ensure()
