set -e
cat > /opt/capteur_exec.bt <<'BT'
#!/usr/bin/env bpftrace
/* Capteur d'execution de processus du laboratoire.
   Point de trace noyau sched:sched_process_exec : chaque exec passe ici. */
tracepoint:sched:sched_process_exec
{
  printf("{\"ts_ns\":%llu,\"pid\":%d,\"tid\":%d,\"uid\":%d,\"comm\":\"%s\",\"fichier\":\"%s\"}\n",
         nsecs, pid, tid, uid, comm, str(args->filename));
}
BT
chmod +x /opt/capteur_exec.bt
nohup bpftrace /opt/capteur_exec.bt > /var/log/capteur_exec.jsonl 2>/var/log/capteur_exec.err &
echo $! > /run/capteur_exec.pid
sleep 6
echo "=== PREUVE 1 : programme charge dans le noyau ==="
bpftool prog show | grep -A3 -B1 tracepoint | head -12
echo
echo "=== PREUVE 2 : lien d'attachement ==="
bpftool link show 2>/dev/null | head -8
echo
echo "=== PREUVE 3 : un evenement REELLEMENT recu apres une operation de test ==="
/usr/bin/id > /dev/null          # operation de test, horodatee
/bin/echo temoin-labo > /dev/null
sleep 3
echo "lignes capturees : $(wc -l < /var/log/capteur_exec.jsonl)"
grep -E '"fichier":"/usr/bin/id"|"fichier":"/bin/echo"' /var/log/capteur_exec.jsonl | tail -3
