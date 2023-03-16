/*
 * Copyright 2017 - 2021, John Wu (@topjohnwu)
 * Copyright 2015, Pierre-Hugues Husson <phh@phh.me>
 * Copyright 2010, Adam Shanks (@ChainsDD)
 * Copyright 2008, Zinx Verituse (@zinxv)
 */

#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <string.h>
#include <sched.h>

#define CMD_GRANT_ROOT 0
#define CMD_GET_VERSION 2
#define DEFAULT_SHELL "/system/bin/sh"

static bool ksuctl(int cmd, void * arg1, void * arg2) {

    int32_t result = 0;
    prctl(0xDEADBEEF, cmd, arg1, arg2, & result);
    return result == 0xDEADBEEF;

}

void elevate() {

    // Talk to Daemon in Kernel Space
    bool status = ksuctl(CMD_GRANT_ROOT, 0, NULL);

    if (!status) {
        fprintf(stderr, "Permission denied\n");
        exit(EXIT_FAILURE);
    }

}

int getver() {

    elevate();

    int32_t version = -1;
    ksuctl(CMD_GET_VERSION, & version, NULL);

    return version;
}

static void usage(int status) {
    FILE *stream = (status == EXIT_SUCCESS) ? stdout : stderr;

    fprintf(stream,
    "KernelSU\n\n"
    "Usage: su [options] [-] [user [argument...]]\n\n"
    "Options:\n"
    "  -c, --command COMMAND         pass COMMAND to the invoked shell\n"
    "  -h, --help                    display this help message and exit\n"
    "  -, -l, --login                pretend the shell to be a login shell\n"
    "  -m, -p,\n"
    "  --preserve-environment        preserve the entire environment\n"
    "  -s, --shell SHELL             use SHELL instead of the default " DEFAULT_SHELL "\n"
    "  -v, --version                 display version number and exit\n"
    "  -V                            display version code and exit\n"
    "  -mm, -M,\n"
    "  --mount-master                force run in the global mount namespace\n\n");
    exit(status);
}

static void switch_to_global_ns() {
    int fd = open("/proc/1/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open /proc/1/ns/mnt");
        return;
    }
    if (setns(fd, CLONE_NEWNS) < 0) {
        perror("setns");
    }
    close(fd);
    return;

}

int main(int argc, char *argv[]) {
    int c;
    int uid = 0;
    char *shell = NULL, *command = NULL;
    bool login = false, keepenv = false, mount_master = false;
    struct option long_opts[] = {
            { "command",                required_argument,  NULL, 'c' },
            { "help",                   no_argument,        NULL, 'h' },
            { "login",                  no_argument,        NULL, 'l' },
            { "preserve-environment",   no_argument,        NULL, 'p' },
            { "shell",                  required_argument,  NULL, 's' },
            { "version",                no_argument,        NULL, 'v' },
            { "context",                required_argument,  NULL, 'z' },
            { "mount-master",           no_argument,        NULL, 'M' },
            { NULL, 0, NULL, 0 },
    };

    for (int i = 0; i < argc; i++) {
        // Replace -cn with -z, -mm with -M for supporting getopt_long
        if (strcmp(argv[i], "-cn") == 0)
            strcpy(argv[i], "-z");
        else if (strcmp(argv[i], "-mm") == 0)
            strcpy(argv[i], "-M");
    }

    while ((c = getopt_long(argc, argv, "c:hlmps:Vvuz:M", long_opts, NULL)) != -1) {
        switch (c) {
            case 'c':
                command = optarg;
                break;
            case 'h':
                usage(EXIT_SUCCESS);
                break;
            case 'l':
                login = true;
                break;
            case 'm':
            case 'p':
                keepenv = true;
                break;
            case 's':
                shell = optarg;
                break;
            case 'v':
                printf("%d:KernelSU\n", getver());
                exit(EXIT_SUCCESS);
            case 'V':
                printf("%d\n", getver());
                exit(EXIT_SUCCESS);
            case 'z':
                // Do nothing, placed here for legacy support :)
                break;
            case 'M':
                mount_master = true;
                break;
            default:
                /* Bionic getopt_long doesn't terminate its error output by newline */
                fprintf(stderr, "\n");
                usage(2);
        }
    }

    if (optind < argc && strcmp(argv[optind], "-") == 0) {
        login = true;
        optind++;
    }
    /* username or uid */
    if (optind < argc) {
        struct passwd *pw;
        pw = getpwnam(argv[optind]);
        if (pw)
            uid = pw->pw_uid;
        else
            uid = atoi(argv[optind]);
        optind++;
    }

    elevate();

    umask(022);

    if (shell == NULL) {
        shell = getenv("SHELL");
    }

    if (shell == NULL) {
        shell = DEFAULT_SHELL;
    }

    if (mount_master) {
        switch_to_global_ns();
    }

    if (!keepenv) {
        struct passwd *pw;
        pw = getpwuid(uid);
        if (pw) {
            setenv("HOME", pw->pw_dir, 1);
            setenv("USER", pw->pw_name, 1);
            setenv("LOGNAME", pw->pw_name, 1);
            setenv("SHELL", shell, 1);
        }
    }

    char *new_argv[4] = { 0 };
    new_argv[0] = login ? "-" : shell;
    if (command != NULL) {
        new_argv[1] = "-c";
        new_argv[2] = command;
    }

    setresuid(uid, uid, uid);
    setresgid(uid, uid, uid);

    execvp(shell, new_argv);
    return 1;
}
