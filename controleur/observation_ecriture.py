"""Attribution noyau bornée d'écritures vfs_write au fichier SQLite du labo.

Ne lit aucun contenu de la base. Un succès vfs_write attribue des octets remis
au noyau, pas leur durabilité, leur valeur métier ou une intention malveillante.
Les chemins mmap/writev/io_uring ne sont pas couverts. Une absence d'événement
n'établit donc pas une absence générale d'écriture.

Référence de syntaxe : https://bpftrace.org/docs/0.21 (kprobe, kretprobe,
retval, sum, interval). retval est explicitement converti en entier signé.
"""
from __future__ import annotations

import inspect
import re

_UNIT = re.compile(r'labo-[a-z0-9][a-z0-9_.-]{0,55}\.service')
_RUN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}')

# Programme fixe : seuls les nombres issus de systemd/stat sont substitués.
# s_dev est un dev_t noyau Linux : major = dev >> 20, minor = dev & 0xfffff.
# Les offsets proviennent du BTF courant via bpftool. Le timer unique évite les
# uprobes BEGIN/END incompatibles avec le binaire bpftrace 0.14 de cette VM.
_PROGRAM = r'''
kprobe:vfs_write /pid == __PID__ && @started && !@stopped/
{
  @depth[tid] = @depth[tid] + 1;
  $file = (uint64)arg0;
  $inode = *(uint64 *)($file + __FILE_INODE__);
  $sb = *(uint64 *)($inode + __INODE_SB__);
  $ino = *(uint64 *)($inode + __INODE_INO__);
  $dev = *(uint32 *)($sb + __SUPER_DEV__);
  if ($ino == __INODE__ && ($dev >> 20) == __MAJOR__ &&
      ($dev & 1048575) == __MINOR__) {
    @matched[tid, @depth[tid]] = 1;
  }
}
kretprobe:vfs_write /pid == __PID__ && @depth[tid] && !@stopped/
{
  $depth = @depth[tid];
  $returned = (int64)retval;
  if (@matched[tid, $depth] && $returned > 0) {
    @events = sum(1);
    @bytes = sum($returned);
  }
  delete(@matched[tid, $depth]);
  if ($depth == 1) { delete(@depth[tid]); }
  else { @depth[tid] = $depth - 1; }
}
interval:s:1
{
  @ticks = @ticks + 1;
  if (@ticks == 1) {
    @events = sum(0); @bytes = sum(0); @started = nsecs;
  }
  if (@ticks == 8) {
    @stopped = 1;
    printf("{\"schema\":\"sawm-vfs-write/v1\",\"pid\":__PID__,\"inode\":__INODE__,\"device_major\":__MAJOR__,\"device_minor\":__MINOR__,\"observed_ns\":%llu,\"complete\":1}\n",
           nsecs - @started);
    print(@events); print(@bytes);
    clear(@events); clear(@bytes); clear(@started); clear(@stopped);
    clear(@matched); clear(@depth); clear(@ticks);
    exit();
  }
}
'''


def _parse_counts(stdout, expected):
    """Trois messages JSON bpftrace 0.14, aucune sortie libre acceptée."""
    import json
    if not isinstance(stdout, str) or len(stdout) > 4096:
        raise ValueError('collector_output_invalid')
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != 3:
        raise ValueError('collector_output_invalid')
    try:
        messages = [json.loads(line) for line in lines]
        value = None
        counts = {}
        for message in messages:
            if not isinstance(message, dict) or set(message) != {'type', 'data'}:
                raise ValueError('collector_output_invalid')
            if message['type'] == 'printf' and value is None:
                value = json.loads(message['data'])
            elif message['type'] == 'map' and isinstance(message['data'], dict):
                data = message['data']
                if len(data) != 1 or set(data) - {'@events', '@bytes'} or set(data) & set(counts):
                    raise ValueError('collector_output_invalid')
                counts.update(data)
            else:
                raise ValueError('collector_output_invalid')
        if not isinstance(value, dict) or set(counts) != {'@events', '@bytes'}:
            raise ValueError('collector_output_invalid')
        if 'write_events' in value or 'written_bytes' in value:
            raise ValueError('collector_output_invalid')
        value.update(write_events=counts['@events'], written_bytes=counts['@bytes'])
    except (ValueError, TypeError):
        raise ValueError('collector_output_invalid') from None
    fields = {'schema', 'pid', 'inode', 'device_major', 'device_minor',
              'write_events', 'written_bytes', 'observed_ns', 'complete'}
    if not isinstance(value, dict) or set(value) != fields or value['schema'] != 'sawm-vfs-write/v1':
        raise ValueError('collector_output_invalid')
    if any(type(value[name]) is not int or not 0 <= value[name] < 2**63
           for name in fields - {'schema'}):
        raise ValueError('collector_output_invalid')
    if any(value.get(name) != number for name, number in expected.items()):
        raise ValueError('collector_target_changed')
    if value['complete'] != 1 or not 6_500_000_000 <= value['observed_ns'] <= 10_000_000_000:
        raise ValueError('collector_window_incomplete')
    if ((value['write_events'] == 0) != (value['written_bytes'] == 0)
            or value['written_bytes'] < value['write_events']):
        raise ValueError('collector_counts_invalid')
    return value


def _layout_from_btf(raw):
    """Offsets issus du BTF courant, avec types et tailles contrôlés."""
    import json
    if not isinstance(raw, str) or len(raw) > 64 * 1024 * 1024:
        raise ValueError('btf_layout_invalid')
    decoded = json.loads(raw)
    entries = decoded.get('types') if isinstance(decoded, dict) else decoded
    if not isinstance(entries, list):
        raise ValueError('btf_layout_invalid')
    types = {t['id']: t for t in entries}
    structs = {}
    for name in ('file', 'inode', 'super_block'):
        found = [t for t in entries if t.get('kind') == 'STRUCT' and t.get('name') == name]
        if len(found) != 1:
            raise ValueError('btf_layout_invalid')
        structs[name] = found[0]

    def resolve(type_id):
        for _ in range(16):
            t = types[type_id]
            if t['kind'] not in ('TYPEDEF', 'CONST', 'VOLATILE', 'RESTRICT', 'TYPE_TAG'):
                return t
            type_id = t['type_id']
        raise ValueError('btf_layout_invalid')

    layout = {}
    specs = [('file', 'f_inode', 8, 'inode', '__FILE_INODE__'),
             ('inode', 'i_sb', 8, 'super_block', '__INODE_SB__'),
             ('inode', 'i_ino', 8, None, '__INODE_INO__'),
             ('super_block', 's_dev', 4, None, '__SUPER_DEV__')]
    for struct_name, member_name, size, pointed_to, token in specs:
        struct = structs[struct_name]
        members = [m for m in struct['members'] if m['name'] == member_name]
        if len(members) != 1:
            raise ValueError('btf_layout_invalid')
        member = members[0]
        bits = member['bits_offset']
        if (type(bits) is not int or bits % 8 or member.get('bitfield_size', 0)
                or not 0 <= bits // 8 <= struct['size'] - size):
            raise ValueError('btf_layout_invalid')
        t = resolve(member['type_id'])
        if pointed_to:
            if t['kind'] != 'PTR' or resolve(t['type_id'])['id'] != structs[pointed_to]['id']:
                raise ValueError('btf_layout_invalid')
        elif (t['kind'] != 'INT' or t['size'] != size or t.get('nr_bits') != size * 8
              or t.get('bits_offset') != 0 or 'SIGNED' in t.get('encoding', '').upper()):
            raise ValueError('btf_layout_invalid')
        layout[token] = bits // 8
    return layout


_REMOTE = r'''
import json,os,pathlib,re,shutil,signal,stat,struct,subprocess,sys,time
deadline=time.monotonic()+12
started=time.monotonic()
result={'schema':'sawm-lab-write-observation/v1','unit':unit,'run_id':run,
        'observed_epoch_ms':int(time.time()*1000),'observation_valid':False,
        'attribution_available':False,'identity_stable':False,
        'write_events':None,'written_bytes':None,'before':None,'after':None,
        'observation_window_s':7,'budget_max_s':12,'collector_timeout':False,
        'collector_returncode':None,'collector_stderr_present':False,
        'lost_events_reported':False,'reason':None,
        'limits':['vfs_write seulement; mmap/writev/io_uring non couverts.',
                  'Octets acceptés par vfs_write; durabilité et intention non établies.',
                  'Absence d’événement ne prouve pas une absence générale d’écriture.']}
held_fd=None
collector=None

def remaining(reserve=0):
    value=deadline-time.monotonic()-reserve
    if value <= 0: raise TimeoutError('observation_budget_expired')
    return value

def identity():
    fields='Id,LoadState,ActiveState,MainPID,ControlGroup,InvocationID'
    p=subprocess.run(['systemctl','show','--property='+fields,'--',unit],
                     capture_output=True,text=True,timeout=min(1.5,remaining()))
    if p.returncode: raise ValueError('systemd_identity_unavailable')
    u=dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line)
    if (u.get('Id') != unit or u.get('LoadState') != 'loaded'
        or u.get('ActiveState') != 'active'
        or not re.fullmatch('[0-9a-f]{32}',u.get('InvocationID',''))):
        raise ValueError('systemd_identity_unavailable')
    pid=int(u.get('MainPID','0'))
    if pid <= 1: raise ValueError('systemd_identity_unavailable')
    cg=u.get('ControlGroup','')
    if (not cg.startswith('/sawm.slice/') or cg.split('/')[-1] != unit
        or any(part in ('.','..') for part in cg.split('/'))):
        raise ValueError('systemd_cgroup_invalid')
    proc=pathlib.Path('/proc')/str(pid)
    process_cgroups=(proc/'cgroup').read_text().splitlines()
    if '0::'+cg not in process_cgroups: raise ValueError('process_cgroup_mismatch')
    fields=(proc/'stat').read_text().rsplit(')',1)[1].split()
    if len(fields) < 20 or fields[0] in ('Z','X'): raise ValueError('process_identity_unavailable')
    starttime=int(fields[19])
    boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not re.fullmatch('[0-9a-f-]{36}',boot) or starttime <= 0:
        raise ValueError('process_identity_unavailable')
    return {'systemd':u,'pid':pid,'starttime_ticks':starttime,'boot_id':boot,
            'cgroup':cg,'invocation_id':u['InvocationID']}

def fixture():
    # Chaque composant est ouvert O_NOFOLLOW; aucune résolution par resolve().
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for name in ('opt','sawm-labo','fixtures','database-defense','run-'+run):
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=child
            st=os.fstat(parent)
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise ValueError('fixture_directory_untrusted')
        fd=os.open('ledger.sqlite',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        st=os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != 0
            or st.st_mode & 0o022 or not 0 < st.st_size <= 1048576):
            os.close(fd);raise ValueError('fixture_file_untrusted')
        return fd,{'inode':st.st_ino,'device':st.st_dev,
                   'device_major':os.major(st.st_dev),'device_minor':os.minor(st.st_dev)}
    finally:os.close(parent)

stage='identity_before_unavailable'
try:
    before=identity();result['before']=before
    stage='fixture_unavailable'
    held_fd,target=fixture();result['target']=target
    stage='collector_unavailable'
    binary=shutil.which('bpftrace')
    if not binary:raise ValueError('collector_unavailable')
    stage='btf_layout_unavailable'
    bpftool=shutil.which('bpftool')
    if not bpftool or struct.calcsize('P') != 8 or sys.byteorder != 'little':
        raise ValueError('btf_layout_unavailable')
    btf=subprocess.run([bpftool,'-j','btf','dump','file','/sys/kernel/btf/vmlinux','format','raw'],
                       capture_output=True,text=True,timeout=min(2,remaining()))
    if btf.returncode:raise ValueError('btf_layout_unavailable')
    layout=_layout_from_btf(btf.stdout)
    result['kernel_layout']={'source':'bpftool-btf-vmlinux','offsets':layout,
                             'kernel_release':os.uname().release}
    expected={'pid':before['pid'],'inode':target['inode'],
              'device_major':target['device_major'],'device_minor':target['device_minor']}
    program=program_template
    for token,offset in layout.items():program=program.replace(token,str(offset))
    for token,name in (('__PID__','pid'),('__INODE__','inode'),
                       ('__MAJOR__','device_major'),('__MINOR__','device_minor')):
        program=program.replace(token,str(expected[name]))
    stage='collector_failed'
    collector=subprocess.Popen([binary,'-q','-f','json','-e',program],stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,text=True,start_new_session=True)
    try:
        stdout,stderr=collector.communicate(timeout=remaining(1.75))
    except subprocess.TimeoutExpired:
        result['collector_timeout']=True
        # Le groupe ne contient que notre collecteur et ses éventuels enfants.
        try:os.killpg(collector.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        stdout,stderr=collector.communicate(timeout=min(.5,remaining()))
    result['collector_returncode']=collector.returncode
    result['collector_stderr_present']=bool(stderr.strip())
    result['lost_events_reported']=bool(re.search(r'\b(lost|dropped)\b',stderr,re.I))
    if result['collector_timeout']:
        result['reason']='collector_timeout'
    elif collector.returncode != 0:
        result['reason']='collector_failed'
    elif result['lost_events_reported']:
        result['reason']='collector_events_lost'
    else:
        stage='collector_output_invalid'
        counts=_parse_counts(stdout,expected)
        stage='identity_after_unavailable'
        after=identity();result['after']=after
        check_fd,after_target=fixture()
        os.close(check_fd)
        if before != after or target != after_target:
            result['reason']='identity_or_fixture_changed'
        else:
            result.update(identity_stable=True,observation_valid=True,
                          attribution_available=counts['write_events'] > 0,
                          write_events=counts['write_events'],written_bytes=counts['written_bytes'],
                          observed_ns=counts['observed_ns'],
                          reason='successful_writes_observed' if counts['write_events'] else 'no_vfs_write_observed')
except Exception:
    # Aucun stderr/nom de processus/contenu de fichier ni message libre exporté.
    result['reason']=stage
finally:
    if collector is not None and collector.poll() is None:
        try:os.killpg(collector.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        try:collector.communicate(timeout=.5)
        except subprocess.TimeoutExpired:pass
    if held_fd is not None:os.close(held_fd)
    result['elapsed_s']=round(time.monotonic()-started,6)
print(json.dumps(result))
'''


def observer_ecritures(unit, run):
    """Observe sept secondes le MainPID exact, budget invité de douze secondes.

    Les valeurs d'appel ne peuvent choisir ni chemin, ni durée, ni programme BPF.
    Les identités inconnues/changées et les collectes incomplètes rendent
    attribution_available=False et laissent les compteurs attribués inconnus.
    """
    if not isinstance(unit, str) or not _UNIT.fullmatch(unit):
        raise ValueError('unite_hors_laboratoire')
    if not isinstance(run, str) or not _RUN.fullmatch(run):
        raise ValueError('run_hors_laboratoire')
    from controleur import vm_labo as vm
    source = ('unit=' + repr(unit) + '\nrun=' + repr(run)
              + '\nprogram_template=' + repr(_PROGRAM) + '\n'
              + inspect.getsource(_parse_counts) + '\n'
              + inspect.getsource(_layout_from_btf) + '\n' + _REMOTE)
    # Le transport inclut une marge SSH; le processus invité impose 12 s.
    return vm.json_code(source, timeout=17)
