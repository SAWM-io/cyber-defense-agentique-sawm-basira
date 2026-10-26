#!/usr/bin/env python3
"""Read-only smoke test on a CI/development host, never a compliance verdict."""
from collections import Counter
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from invite.agent_labo.posture_securite import collect, status_for

result=collect()
assert result['schema']=='sawm-posture-os/v1'
assert len(result['controls'])==12
assert len({c['id'] for c in result['controls']})==12
for control in result['controls']:
    assert control['status'] in {'satisfait','ecart','inconnu'}
    if control['status']!='inconnu':
        assert status_for(control['id'],control['observed_value'])==control['status']
print(json.dumps({'kind':'read-only-host-probe','platform':sys.platform,
                  'certification':False,'controls':len(result['controls']),
                  'counts':dict(Counter(c['status'] for c in result['controls']))}))
