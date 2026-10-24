"""Read-only, bounded SSH observations from root sshd's system journal.

No login credentials, raw journal text or command lines leave this module.
It can suggest an investigation; it never edits sshd, accounts or a firewall.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
import hashlib
import ipaddress
import json
import re
import subprocess
import threading
import time

MAX_ROWS = 128
WINDOW_MS = 300_000
MAX_BYTES = 262144
_ACCOUNT = r'(?P<account>[A-Za-z0-9_.@-]{1,128})'
_PEER = r' from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>[0-9]{1,5})'
_METHOD = r'(?P<method>password|publickey|keyboard-interactive/pam|hostbased)'
_FAILED = re.compile(r'^Failed '+_METHOD+r' for (?:invalid user )?'+_ACCOUNT+_PEER+r'(?: ssh2)?(?:: [^\r\n]{0,512})?(?: \[preauth\])?$')
_ACCEPTED = re.compile(r'^Accepted '+_METHOD+r' for '+_ACCOUNT+_PEER+r'(?: ssh2)?(?:: [^\r\n]{0,512})?$')
_INVALID = re.compile(r'^Invalid user '+_ACCOUNT+_PEER+r'(?: \[preauth\])?$')
_FINGERPRINT = re.compile(r'(?:^| )SHA256:([A-Za-z0-9+/]{20,100}=*)(?: |$)')
_HEX = re.compile(r'[0-9a-f]{32}')
LIMITS = [
    'Lecture seule : aucun blocage SSH ni changement de compte.',
    'Un compte pseudonymisé, une IP ou une clé ne prouvent pas une identité humaine.',
    'Un succès SSH ne prouve pas un abus ; son activité doit être attribuée séparément.',
    'Les rapprochements multi-IP sont des hypothèses, sans propagation de blocage.',
    'Aucune géolocalisation externe ; IP privées ou réservées non applicables.',
    'Fenêtre bornée et journal du noyau non attesté face à un administrateur compromis.',
]


def _hash(kind, value):
    return hashlib.sha256(('sawm-ssh-'+kind+'/v1\0'+value).encode()).hexdigest()


def normalize(row, *, now_ms):
    """Trust journald metadata, never a user-chosen SYSLOG_IDENTIFIER alone."""
    if (type(row) is not dict or row.get('_UID') != '0'
            or row.get('_SYSTEMD_UNIT') not in ('ssh.service', 'sshd.service')
            or row.get('_COMM') != 'sshd'
            or row.get('_EXE') not in ('/usr/sbin/sshd', '/usr/local/sbin/sshd')):
        return None
    message = row.get('MESSAGE')
    if not isinstance(message, str) or len(message) > 1024:
        return None
    matched, outcome = None, None
    for pattern, label in ((_FAILED, 'rejected'), (_ACCEPTED, 'accepted'), (_INVALID, 'invalid_account')):
        matched = pattern.fullmatch(message)
        if matched:
            outcome = label
            break
    if matched is None:
        return None
    try:
        stamp = row['__REALTIME_TIMESTAMP']
        pid = row['_PID']
        if type(stamp) is not str or not stamp.isdigit() or type(pid) is not str or not pid.isdigit():
            return None
        observed_ms = int(stamp)//1000
        if not 0 <= now_ms-observed_ms <= WINDOW_MS or not 1 < int(pid) <= 2**31-1:
            return None
        boot = row['_BOOT_ID']
        if not isinstance(boot,str) or not _HEX.fullmatch(boot):
            return None
        peer = ipaddress.ip_address(matched['ip'])
        port = int(matched['port'])
        if not 1 <= port <= 65535:
            return None
    except (KeyError, ValueError, TypeError):
        return None
    account = _hash('account', matched['account'])
    cursor = row.get('__CURSOR')
    identity = (cursor if type(cursor) is str and len(cursor)<=4096 else
                json.dumps([boot,stamp,pid,outcome,str(peer),port,account],separators=(',',':')))
    event = {'schema':'sawm-ssh-observation/v1','id':_hash('event',identity)[:32],
             'observed_ms':observed_ms,'source_ip':str(peer),'source_port':port,
             'destination_port':22,'account_hash':account,'outcome':outcome,
             'destination_port_source':'lab_configuration',
             'method':matched.groupdict().get('method') or 'unknown',
             'sshd_pid':int(pid),'boot_id':boot,'session_id':None,
             'source':'journald_root_sshd','human_identity_established':False,
             'geography':'unknown' if peer.is_global else 'not_applicable',
             'credential_fingerprint_hash':None}
    session = row.get('_AUDIT_SESSION')
    if type(session) is str and session.isdigit() and int(session)<4294967295:
        event['session_id'] = int(session)
    fingerprint = _FINGERPRINT.search(message)
    if fingerprint:
        event['credential_fingerprint_hash'] = _hash('credential',fingerprint[1])
    return event


def summarize(events, *, now_ms):
    """Deduplicate journal records and correlate actual distinct connections."""
    recent = {}
    for event in events:
        if 0 <= now_ms-event['observed_ms'] <= WINDOW_MS:
            recent[event['id']] = event
    rows = sorted(recent.values(),key=lambda e:e['observed_ms'])[-MAX_ROWS:]
    groups = defaultdict(lambda:defaultdict(set))
    peers = defaultdict(set)
    peer_evidence = defaultdict(list)
    account_evidence = defaultdict(list)
    for event in rows:
        if event['outcome'] not in ('rejected','invalid_account'):
            continue
        connection = (event['boot_id'],event['sshd_pid'],event['source_port'])
        groups[event['account_hash']][event['source_ip']].add(connection)
        peers[event['source_ip']].add(connection)
        peer_evidence[event['source_ip']].append(event)
        account_evidence[event['account_hash']].append(event)

    def episode(evidence):
        # Derived from actual journal events, never the polling clock. A later
        # equivalent series of connections must not be suppressed forever.
        identities = sorted({event['id'] for event in evidence})
        return {'episode_id':_hash('episode',','.join(identities))[:24],
                'first_observed_ms':min(event['observed_ms'] for event in evidence),
                'last_observed_ms':max(event['observed_ms'] for event in evidence),
                'evidence_count':len(identities)}
    campaigns = []
    for account, sources in sorted(groups.items()):
        if len(sources)<2:
            continue
        campaigns.append({'id':_hash('campaign',account+','.join(sorted(sources)))[:24],
            **episode(account_evidence[account]),
            'hypothese':'echecs_ssh_multi_ip_meme_compte','account_hash':account,
            'sources':[{'ip':ip,'connections':len(connections),
                        'geography':'unknown' if ipaddress.ip_address(ip).is_global else 'not_applicable'}
                       for ip,connections in sorted(sources.items())],
            'recommandation':'signaler','identite_commune_etablie':False,
            'blocage_propage':False,'technique_confirmee':False,
            'mappings_attack':['T1110']})
    alerts = []
    for peer, connections in sorted(peers.items()):
        if len(connections)>=3:
            alerts.append({'id':_hash('alert',peer)[:24], 'source_ip':peer,
                           **episode(peer_evidence[peer]),
                           'raison':'refus_ssh_repetes','connections':len(connections),
                           'priorite':'haute' if len(connections)>=5 else 'moyenne',
                           'recommandation':'signaler','block_performed':False})
    counts = dict(Counter(x['outcome'] for x in rows))
    return {'events':rows[-32:],'counts':counts,'campagnes':campaigns,'alertes':alerts,
            'observed_events':len(rows),
            'age_ms':now_ms-max(x['observed_ms'] for x in rows) if rows else None,
            'window_ms':WINDOW_MS,'human_identity_established':False,'block_performed':False}


class SSHObserver:
    def __init__(self):
        self.lock=threading.Lock()
        self.events=deque(maxlen=MAX_ROWS)
        self.seen=set()
        self.last_poll=0.0
        self.state={'schema':'sawm-ssh-telemetry/v1','available':False,'status':'non_lu',
                    'events':[],'counts':{},'campagnes':[],'alertes':[],
                    'invalid_events':0,'truncated':False,'limits':LIMITS}

    def sample(self, *, now_ms=None, force=False):
        now_ms=int(time.time()*1000) if now_ms is None else now_ms
        with self.lock:
            if not force and time.monotonic()-self.last_poll<2:
                return {**self.state,**summarize(self.events,now_ms=now_ms)}
            self.last_poll=time.monotonic()
            command=['/usr/bin/journalctl','-u','ssh.service','-u','sshd.service',
                     '--since','5 minutes ago','--reverse','-n',str(MAX_ROWS),'--no-pager',
                     '--grep=^(Failed |Accepted |Invalid user )',
                     '--output=json','--output-fields=MESSAGE,_UID,_COMM,_EXE,_SYSTEMD_UNIT,_PID,_BOOT_ID,_AUDIT_SESSION,__REALTIME_TIMESTAMP,__CURSOR']
            try:
                result=subprocess.run(command,capture_output=True,text=True,timeout=.75,
                                      env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
                if result.returncode and not (result.returncode==1 and not result.stdout and not result.stderr):
                    raise RuntimeError('journal_read_failed')
                raw=result.stdout
                too_large=len(raw.encode())>MAX_BYTES
                lines=raw.splitlines()[-MAX_ROWS:]
                if too_large:
                    # Do not silently parse a partially truncated JSON event.
                    lines=[line for line in lines if len(line)<=8192]
                invalid=0
                # journalctl --reverse gives newest first; keep the bounded
                # deque chronological so eviction removes older evidence.
                for line in reversed(lines):
                    if len(line)>8192:
                        invalid+=1;continue
                    try:row=json.loads(line)
                    except (ValueError,TypeError):invalid+=1;continue
                    event=normalize(row,now_ms=now_ms)
                    if event and event['id'] not in self.seen:
                        self.events.append(event);self.seen.add(event['id'])
                if len(self.seen)>MAX_ROWS*4:
                    self.seen={x['id'] for x in self.events}
                self.state.update(available=True,status='journal_lu',invalid_events=invalid,
                                  truncated=too_large or len(lines)>=MAX_ROWS,
                                  polled_at_ms=now_ms)
            except (OSError,subprocess.TimeoutExpired,RuntimeError,UnicodeError):
                self.state.update(available=False,status='journal_indisponible',polled_at_ms=now_ms)
            return {**self.state,**summarize(self.events,now_ms=now_ms)}


_OBSERVER=SSHObserver()


def etat():
    return _OBSERVER.sample()
