// Chargeur de la politique de refus LSM.
//
// Charge lsm_refus.bpf.o, attache les deux crochets LSM, puis EPINGLE les
// liens et les tables dans bpffs. L'epinglage est ce qui permet au chargeur
// de rendre la main : la politique survit a la fin du processus, mais reste
// retirable par le proprietaire (rm des epingles). C'est deliberé : un
// mecanisme qu'on ne peut pas retirer n'est pas une defense, c'est une panne.
//
// Compilation :
//   clang -O2 -o lsm_charge lsm_charge.c -lbpf -lelf -lz
//
// Usage :
//   lsm_charge charger   -> charge, attache, epingle sous /sys/fs/bpf/sawm
//   lsm_charge retirer   -> retire les epingles (la politique tombe)

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RACINE "/sys/fs/bpf/sawm"
#define OBJET  "/opt/sawm-labo/lsm_refus.bpf.o"

static int journal(enum libbpf_print_level niveau, const char *format,
                   va_list args)
{
    if (niveau == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

static int epingler_lien(struct bpf_program *prog, const char *nom)
{
    struct bpf_link *lien = bpf_program__attach(prog);
    /* libbpf rend un POINTEUR D'ERREUR, pas NULL : tester !lien seul fait
       dereferencer 0xfffffffffffffdf4 plus bas, ce qui vaut un segfault et
       masque la vraie cause (-524 ENOTSUPP sur un noyau sans trampoline). */
    long err = libbpf_get_error(lien);
    if (err) {
        fprintf(stderr, "attachement de %s impossible : %s (%ld)\n", nom,
                strerror((int)-err), err);
        if (err == -524)
            fprintf(stderr,
                    "  -> ENOTSUPP : ce noyau n'expose pas le type de "
                    "programme LSM. Sur arm64 les trampolines BPF exigent "
                    "un noyau 6.0 ou superieur.\n");
        return -1;
    }
    char chemin[256];
    snprintf(chemin, sizeof(chemin), RACINE "/lien_%s", nom);
    unlink(chemin);
    if (bpf_link__pin(lien, chemin)) {
        fprintf(stderr, "epinglage de %s impossible : %s\n", chemin,
                strerror(errno));
        return -1;
    }
    printf("  crochet %-22s attache et epingle : %s\n", nom, chemin);
    return 0;
}

static int epingler_table(struct bpf_object *obj, const char *nom)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, nom);
    if (!map) {
        fprintf(stderr, "table %s introuvable\n", nom);
        return -1;
    }
    char chemin[256];
    snprintf(chemin, sizeof(chemin), RACINE "/%s", nom);
    unlink(chemin);
    if (bpf_map__pin(map, chemin)) {
        fprintf(stderr, "epinglage de la table %s impossible : %s\n", nom,
                strerror(errno));
        return -1;
    }
    printf("  table   %-22s epinglee          : %s\n", nom, chemin);
    return 0;
}

static int retirer(void)
{
    const char *cibles[] = {
        RACINE "/lien_refus_ouverture", RACINE "/lien_refus_execution",
        RACINE "/inodes_refusees",      RACINE "/inodes_non_executables",
        RACINE "/uids_temoins",         RACINE "/compteurs",
        RACINE "/refus_journal",        NULL,
    };
    int n = 0;
    for (int i = 0; cibles[i]; i++)
        if (unlink(cibles[i]) == 0) {
            printf("  retire : %s\n", cibles[i]);
            n++;
        }
    rmdir(RACINE);
    printf("politique retiree (%d epingles)\n", n);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "retirer") == 0)
        return retirer();

    libbpf_set_print(journal);

    if (mkdir(RACINE, 0700) && errno != EEXIST) {
        fprintf(stderr, "bpffs indisponible (%s) : %s\n", RACINE,
                strerror(errno));
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file(OBJET, NULL);
    if (!obj) {
        fprintf(stderr, "ouverture de %s impossible : %s\n", OBJET,
                strerror(errno));
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "chargement refuse par le verificateur : %s\n",
                strerror(errno));
        return 1;
    }
    printf("objet charge : %s\n", OBJET);

    struct bpf_program *ouv = bpf_object__find_program_by_name(obj,
                                                              "refus_ouverture");
    struct bpf_program *exe = bpf_object__find_program_by_name(obj,
                                                              "refus_execution");
    if (!ouv || !exe) {
        fprintf(stderr, "programmes LSM introuvables dans l'objet\n");
        return 1;
    }
    if (epingler_lien(ouv, "refus_ouverture") ||
        epingler_lien(exe, "refus_execution"))
        return 1;

    const char *tables[] = { "inodes_refusees", "inodes_non_executables",
                             "uids_temoins", "compteurs", "refus_journal",
                             NULL };
    for (int i = 0; tables[i]; i++)
        if (epingler_table(obj, tables[i]))
            return 1;

    printf("politique en place. Les tables sont VIDES : rien n'est refuse "
           "tant que l'executeur n'y a pas inscrit d'inode.\n");
    return 0;
}
