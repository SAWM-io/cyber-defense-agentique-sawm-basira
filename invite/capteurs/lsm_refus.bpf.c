// SPDX-License-Identifier: GPL-2.0-only
// Politique de refus au niveau du noyau, par crochet LSM eBPF.
//
// Ce programme ne decide rien : il APPLIQUE une politique dont le contenu vit
// dans des tables BPF, remplies par l'executeur local apres validation contre
// le manifeste. Le modele SAWM ne peut pas ecrire ici ; il propose une action
// typee, l'executeur la verifie, puis l'executeur seul pose l'inode dans la
// table. C'est la frontiere exigee par le mandat : les droits viennent du
// proprietaire, l'executeur les verifie, le noyau les applique.
//
// Crochets utilises :
//   lsm/file_open        - refuse l'ouverture d'une fixture protegee
//   lsm/bprm_check_security - refuse l'execution d'un binaire protege
//
// Un refus vaut -EPERM rendu par le noyau a l'appelant : ce n'est pas une
// notification, c'est l'operation qui n'a pas lieu.
//
// Garde-fou : les tables demarrent VIDES. Un inode absent de la table n'est
// jamais refuse. Il n'existe aucun mode « refuser tout ».

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

// Inodes dont l'ouverture est refusee. Cle : numero d'inode. Valeur :
// identifiant de decision (tronque), pour rattacher un refus a sa cause.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u64);
} inodes_refusees SEC(".maps");

// Inodes dont l'EXECUTION est refusee (crochet distinct de l'ouverture).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u64);
} inodes_non_executables SEC(".maps");

// Identites temoins, explicitement exemptees : elles prouvent que le refus est
// CIBLE et non un blocage general. Sans ce temoin, « plus rien ne marche »
// serait indiscernable de « la politique fonctionne ».
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} uids_temoins SEC(".maps");

// Compteurs : 0 = refus d'ouverture, 1 = exemptions temoin,
//             2 = refus d'execution, 3 = ouvertures vues sur inode surveille.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} compteurs SEC(".maps");

// Journal des refus, vers l'espace utilisateur. Un refus qui n'est pas
// observable ne se distingue pas d'une panne.
struct evenement_refus {
    __u64 horodatage_ns;
    __u64 inode;
    __u64 decision;
    __u32 pid;
    __u32 uid;
    __u32 genre;          // 0 = ouverture, 1 = execution
    char  comm[16];
};

// Tampon circulaire : bpf_ringbuf_output n'exige pas le contexte du
// programme, contrairement a bpf_perf_event_output. Dans un crochet LSM
// declare avec BPF_PROG, le premier argument est l'objet vise (struct file *),
// PAS le contexte : le verificateur refuse le programme si on le lui passe.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);
} refus_journal SEC(".maps");

static __always_inline void incrementer(__u32 index)
{
    __u64 *c = bpf_map_lookup_elem(&compteurs, &index);
    if (c)
        __sync_fetch_and_add(c, 1);
}

static __always_inline void publier(__u64 ino, __u64 decision, __u32 genre)
{
    struct evenement_refus e = {};
    e.horodatage_ns = bpf_ktime_get_ns();
    e.inode = ino;
    e.decision = decision;
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e.genre = genre;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_ringbuf_output(&refus_journal, &e, sizeof(e), 0);
}

SEC("lsm/file_open")
int BPF_PROG(refus_ouverture, struct file *file)
{
    __u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    __u64 *decision = bpf_map_lookup_elem(&inodes_refusees, &ino);
    if (!decision)
        return 0;                       // hors politique : on ne touche a rien

    incrementer(3);

    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (bpf_map_lookup_elem(&uids_temoins, &uid)) {
        incrementer(1);                 // le temoin passe : refus cible, prouve
        return 0;
    }

    incrementer(0);
    publier(ino, *decision, 0);
    return -EPERM;                      // le noyau refuse. Pas une alerte.
}

SEC("lsm/bprm_check_security")
int BPF_PROG(refus_execution, struct linux_binprm *bprm)
{
    __u64 ino = BPF_CORE_READ(bprm, file, f_inode, i_ino);
    __u64 *decision = bpf_map_lookup_elem(&inodes_non_executables, &ino);
    if (!decision)
        return 0;

    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (bpf_map_lookup_elem(&uids_temoins, &uid)) {
        incrementer(1);
        return 0;
    }

    incrementer(2);
    publier(ino, *decision, 1);
    return -EPERM;
}
