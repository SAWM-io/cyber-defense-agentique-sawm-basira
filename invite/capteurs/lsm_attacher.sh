cd /opt/sawm-labo
echo "=== libbpf disponible en paquet ==="
apt-cache policy libbpf-dev libbpf1 2>/dev/null | grep -E "^libbpf|Candidate|Installed" | head -6
echo
echo "=== voie bpftool : chargement + attachement automatique ==="
rm -rf /sys/fs/bpf/sawm; mkdir -p /sys/fs/bpf/sawm
bpftool prog loadall lsm_refus.bpf.o /sys/fs/bpf/sawm pinmaps /sys/fs/bpf/sawm autoattach 2>&1 | head -6
echo "code de retour : $?"
echo
echo "=== ce qui est epingle ==="
ls -la /sys/fs/bpf/sawm/ 2>/dev/null
echo
echo "=== programmes LSM charges ==="
bpftool prog show 2>/dev/null | grep -B1 -A2 lsm | head -12
echo
echo "=== liens d'attachement ==="
bpftool link show 2>/dev/null | head -10
