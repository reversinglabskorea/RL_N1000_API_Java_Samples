=== active.c
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <getopt.h>
#include "systemd/sd-daemon.h"
#include "socket-util.h"
#include "build.h"
#include "log.h"
#include "strv.h"
#include "macro.h"
static char** arg_listen = NULL;
static bool arg_accept = false;
static char** arg_args = NULL;
static char** arg_setenv = NULL;
static int add_epoll(int epoll_fd, int fd) {
        struct epoll_event ev = {
                .events = EPOLLIN
        };
        int r;
        assert(epoll_fd >= 0);
        assert(fd >= 0);
        ev.data.fd = fd;
        r = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
        if (r < 0) {
                log_error("Failed to add event on epoll fd:%d for fd:%d: %m", epoll_fd, fd);
                return -errno;
        }
        return 0;
}
static int open_sockets(int *epoll_fd, bool accept) {
        char **address;
        int n, fd, r;
        int count = 0;
        n = sd_listen_fds(true);
        if (n < 0) {
                log_error("Failed to read listening file descriptors from environment: %s",
                          strerror(-n));
                return n;
        }
        if (n > 0) {
                log_info("Received %i descriptors via the environment.", n);
                for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
                        r = fd_cloexec(fd, arg_accept);
                        if (r < 0)
                                return r;
                        count ++;
                }
        }
        /* Close logging and all other descriptors */
        if (arg_listen) {
                int except[3 + n];
                for (fd = 0; fd < SD_LISTEN_FDS_START + n; fd++)
                        except[fd] = fd;
                log_close();
                close_all_fds(except, 3 + n);
        }
        /** Note: we leak some fd's on error here. I doesn't matter
         *  much, since the program will exit immediately anyway, but
         *  would be a pain to fix.
         */
        STRV_FOREACH(address, arg_listen) {
                fd = make_socket_fd(LOG_DEBUG, *address, SOCK_STREAM | (arg_accept*SOCK_CLOEXEC));
                if (fd < 0) {
                        log_open();
                        log_error("Failed to open '%s': %s", *address, strerror(-fd));
                        return fd;
                }
                assert(fd == SD_LISTEN_FDS_START + count);
                count ++;
        }
        if (arg_listen)
                log_open();
        *epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (*epoll_fd < 0) {
                log_error("Failed to create epoll object: %m");
                return -errno;
        }
        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + count; fd++) {
                _cleanup_free_ char *name = NULL;
                getsockname_pretty(fd, &name);
                log_info("Listening on %s as %i.", strna(name), fd);
                r = add_epoll(*epoll_fd, fd);
                if (r < 0)
                        return r;
        }
        return count;
}


=== a20.c

#include "boot.h"
#define MAX_8042_LOOPS  100000
#define MAX_8042_FF 32
static int empty_8042(void)
{
    u8 status;
    int loops = MAX_8042_LOOPS;
    int ffs   = MAX_8042_FF;
    while (loops--) {
        io_delay();
        status = inb(0x64);
        if (status == 0xff) {
            /* FF is a plausible, but very unlikely status */
            if (!--ffs)
                return -1; /* Assume no KBC present */
        }
        if (status & 1) {
            /* Read and discard input data */
            io_delay();
            (void)inb(0x60);
        } else if (!(status & 2)) {
            /* Buffers empty, finished! */
            return 0;
        }
    }
    return -1;
}
/* Returns nonzero if the A20 line is enabled.  The memory address
   used as a test is the int $0x80 vector, which should be safe. */
#define A20_TEST_ADDR   (4*0x80)
#define A20_TEST_SHORT  32
#define A20_TEST_LONG   2097152 /* 2^21 */
static int a20_test(int loops)
{
    int ok = 0;
    int saved, ctr;
    set_fs(0x0000);
    set_gs(0xffff);
    saved = ctr = rdfs32(A20_TEST_ADDR);
    while (loops--) {
        wrfs32(++ctr, A20_TEST_ADDR);
        io_delay(); /* Serialize and make delay constant */
        ok = rdgs32(A20_TEST_ADDR+0x10) ^ ctr;
        if (ok)
            break;
    }
    wrfs32(saved, A20_TEST_ADDR);
    return ok;
}
/* Quick test to see if A20 is already enabled */
static int a20_test_short(void)
{
    return a20_test(A20_TEST_SHORT);
}
/* Longer test that actually waits for A20 to come on line; this
   is useful when dealing with the KBC or other slow external circuitry. */
static int a20_test_long(void)
{
    return a20_test(A20_TEST_LONG);
}
static void enable_a20_bios(void)
{
    struct biosregs ireg;
    initregs(&ireg);
    ireg.ax = 0x2401;
    intcall(0x15, &ireg, NULL);
}
static void enable_a20_kbc(void)
{
    empty_8042();
    outb(0xd1, 0x64);   /* Command write */
    empty_8042();
    outb(0xdf, 0x60);   /* A20 on */
    empty_8042();
    outb(0xff, 0x64);   /* Null command, but UHCI wants it */
    empty_8042();
}

=== boot-loader.c

static char *loader_fragment_read_title(const char *fragment) {
        FILE *f;
        char line[LINE_MAX];
        char *title = NULL;
        f = fopen(fragment, "re");
        if (!f)
                return NULL;
        while (fgets(line, sizeof(line), f) != NULL) {
                char *s;
                size_t l;
                l = strlen(line);
                if (l < 1)
                        continue;
                if (line[l-1] == '\n')
                        line[l-1] = '\0';
                s = line;
                while (isspace(s[0]))
                        s++;
                if (s[0] == '#')
                        continue;
                if (!startswith(s, "title"))
                        continue;
                s += strlen("title");
                if (!isspace(s[0]))
                        continue;
                while (isspace(s[0]))
                        s++;
                title = strdup(s);
                break;
        }
        fclose(f);
        return title;
}
int boot_loader_read_entries(struct boot_info *info) {
        _cleanup_strv_free_ char **files = NULL;
        static const char *loader_dir[] = { "/boot/loader/entries", NULL};
        unsigned int count;
        unsigned int i;
        int err;
        err = conf_files_list_strv(&files, ".conf", NULL, loader_dir);
        if (err < 0)
                return err;
        count = strv_length(files);
        info->loader_entries = new0(struct boot_info_entry, count);
        if (!info->loader_entries)
                return -ENOMEM;
        for (i = 0; i < count; i++) {
                info->loader_entries[i].title = loader_fragment_read_title(files[i]);
                info->loader_entries[i].path = strdup(files[i]);
                if (!info->loader_entries[i].title || !info->loader_entries[i].path) {
                        free(info->loader_entries[i].title);
                        free(info->loader_entries[i].path);
                        return -ENOMEM;
                }
                info->loader_entries_count++;
        }
        return 0;
}
int boot_loader_find_active_entry(struct boot_info *info, const char *loader_active) {
        char *fn;
        unsigned int i;
        if (!loader_active)
                return -ENOENT;
        if (info->loader_entries_count == 0)
                return -ENOENT;
        if (asprintf(&fn, "/boot/loader/entries/%s.conf", loader_active) < 0)
                return -ENOMEM;
        for (i = 0; i < info->loader_entries_count; i++) {
                if (streq(fn, info->loader_entries[i].path)) {
                        info->loader_entry_active = i;
                        break;
                }
        }
        free(fn);
        return 0;
}