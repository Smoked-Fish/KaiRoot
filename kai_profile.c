#define _GNU_SOURCE
#include "kai_profile.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>

enum {
  P_STR,
  P_U32,
};

struct field {
  const char *key;
  unsigned char type;
  unsigned char required;
  unsigned short offset;
  unsigned short size;
};

#define F_STR(key, member, req) {key, P_STR, req, offsetof(struct kai_profile, member), (unsigned short)sizeof(((struct kai_profile *)0)->member)}
#define F_U32(key, member, req) {key, P_U32, req, offsetof(struct kai_profile, member), 4u}

static const struct field g_fields[] = {
    F_STR("profile.target", target, 1),
    F_STR("match.ro.product.device", match_product, 1),
    F_STR("match.ro.product.model", match_model, 1),
    F_STR("match.ro.build.fingerprint", match_fingerprint, 1),
    F_STR("match.ro.build.version.incremental", match_incremental, 1),
    F_STR("match.uname.release", match_kernel_release, 1),
    F_STR("match.uname.machine", match_machine, 1),
    F_STR("exploit.path", exploit_path, 1),
    F_U32("exploit.waiter_core", waiter_core, 1),
    F_U32("exploit.consumer_core", consumer_core, 1),
    F_U32("exploit.consumer_delay_us", consumer_delay_us, 1),
    F_U32("address.init_task", init_task, 1),
    F_U32("address.pi_task", pi_task, 1),
    F_U32("address.ashmem_fops", ashmem_fops, 1),
    F_U32("address.ashmem_misc_fops", ashmem_misc_fops, 1),
    F_U32("address.ashmem_open", ashmem_open, 1),
    F_U32("address.ashmem_release", ashmem_release, 1),
    F_U32("address.ashmem_ioctl", ashmem_ioctl, 1),
    F_U32("address.ashmem_mmap", ashmem_mmap, 1),
    F_U32("address.configfs_read_file", configfs_read_file, 1),
    F_U32("address.configfs_write_file", configfs_write_file, 1),
    F_U32("address.init_cred", init_cred, 0),
    F_U32("address.selinux_enforcing", selinux_enforcing, 0),
    F_U32("offset.task_tasks", task_tasks_off, 1),
    F_U32("offset.task_real_cred", task_real_cred_off, 1),
    F_U32("offset.task_cred", task_cred_off, 1),
    F_U32("offset.task_comm", task_comm_off, 1),
    F_U32("analysis.kernel_image_base", kernel_image_base, 1),
    F_U32("analysis.kernel_size", kernel_size, 1),
};

#define FIELD_COUNT (sizeof(g_fields) / sizeof(g_fields[0]))

static void set_error(char *error, size_t error_size, const char *format, ...) {
  if (!error || !error_size)
    return;
  va_list ap;
  va_start(ap, format);
  vsnprintf(error, error_size, format, ap);
  va_end(ap);
}

static char *trim(char *text) {
  while (isspace((unsigned char)*text))
    text++;
  char *end = text + strlen(text);
  while (end > text && isspace((unsigned char)end[-1]))
    *--end = 0;
  return text;
}

static const struct field *find_field(const char *key) {
  for (unsigned i = 0; i < FIELD_COUNT; i++)
    if (!strcmp(g_fields[i].key, key))
      return &g_fields[i];
  return NULL;
}

static int ignored_key(const char *key) {
  if (!strncmp(key, "analysis.", 9))
    return 1;
  return !strcmp(key, "profile.version") || !strcmp(key, "profile.verification") || !strcmp(key, "address.policydb") ||
         !strcmp(key, "address.sidtab");
}

static int assign_field(struct kai_profile *profile, uint32_t *present, const struct field *f, const char *value,
                        char *error, size_t error_size) {
  uint32_t bit = 1u << (f - g_fields);
  if (*present & bit) {
    set_error(error, error_size, "duplicate profile key: %s", f->key);
    return 0;
  }
  if (!*value)
    return 1;

  *present |= bit;
  if (f->type == P_STR) {
    if (strlen(value) >= f->size) {
      set_error(error, error_size, "value too long for profile key: %s", f->key);
      return 0;
    }
    strcpy((char *)profile + f->offset, value);
    return 1;
  }
  errno = 0;
  char *end = NULL;
  unsigned long parsed = strtoul(value, &end, 0);
  if (errno || !end || *end || end == value || parsed > UINT32_MAX) {
    set_error(error, error_size, "invalid integer for profile key: %s", f->key);
    return 0;
  }
  *(uint32_t *)((char *)profile + f->offset) = (uint32_t)parsed;
  return 1;
}

// todo wildcard
static int finish_profile(struct kai_profile *profile, uint32_t present, const char *path, char *error,
                          size_t error_size) {
  char missing[512];
  missing[0] = 0;
  size_t used = 0;
  for (unsigned i = 0; i < FIELD_COUNT; i++) {
    if (!g_fields[i].required || (present & (1u << i)))
      continue;
    int n = snprintf(missing + used, sizeof(missing) - used, "%s%s", used ? ", " : "", g_fields[i].key);
    if (n < 0 || (size_t)n >= sizeof(missing) - used)
      break;
    used += (size_t)n;
  }
  if (used) {
    set_error(error, error_size, "%s: missing required profile fields: %s", path, missing);
    return 0;
  }
  if (!strcmp(profile->match_product, "*") || !strcmp(profile->match_fingerprint, "*") ||
      !strcmp(profile->match_incremental, "*") || !strcmp(profile->match_kernel_release, "*") ||
      !strcmp(profile->match_machine, "*")) {
    set_error(error, error_size, "%s: only match.ro.product.model may use a wildcard", path);
    return 0;
  }
  return 1;
}

static int parse_profile(const char *path, struct kai_profile *profile, char *error, size_t error_size) {
  memset(profile, 0, sizeof(*profile));
  uint32_t present = 0;

  FILE *file = fopen(path, "re");
  if (!file) {
    set_error(error, error_size, "cannot open %s: %s", path, strerror(errno));
    return 0;
  }
  char line[1024];
  unsigned line_number = 0;
  int ok = 1;
  while (ok && fgets(line, sizeof(line), file)) {
    line_number++;
    if (!strchr(line, '\n') && !feof(file)) {
      set_error(error, error_size, "%s:%u: line is too long", path, line_number);
      ok = 0;
      break;
    }
    char *entry = trim(line);
    if (!*entry || *entry == '#')
      continue;
    char *separator = strchr(entry, '=');
    if (!separator) {
      set_error(error, error_size, "%s:%u: expected key=value", path, line_number);
      ok = 0;
      break;
    }
    *separator = 0;
    char *key = trim(entry);
    char *value = trim(separator + 1);
    if (!*key) {
      set_error(error, error_size, "%s:%u: empty key", path, line_number);
      ok = 0;
      break;
    }
    const struct field *f = find_field(key);
    if (f) {
      char detail[256];
      detail[0] = 0;
      if (!assign_field(profile, &present, f, value, detail, sizeof(detail))) {
        set_error(error, error_size, "%s:%u: %s", path, line_number, detail);
        ok = 0;
      }
    } else if (!ignored_key(key)) {
      set_error(error, error_size, "%s:%u: unknown profile key: %s", path, line_number, key);
      ok = 0;
    }
  }
  if (ok && ferror(file)) {
    set_error(error, error_size, "cannot read %s: %s", path, strerror(errno));
    ok = 0;
  }
  fclose(file);
  if (ok)
    return finish_profile(profile, present, path, error, error_size);
  return 0;
}

static int read_property(const char *name, char *destination, size_t destination_size) {
  char value[PROP_VALUE_MAX] = {0};
  int length = __system_property_get(name, value);
  if (length <= 0 || (size_t)length >= destination_size)
    return 0;
  memcpy(destination, value, (size_t)length + 1);
  return 1;
}

int kai_runtime_read(struct kai_runtime *runtime, char *error, size_t error_size) {
  memset(runtime, 0, sizeof(*runtime));
  if (!read_property("ro.product.device", runtime->product, sizeof(runtime->product)) ||
      !read_property("ro.product.model", runtime->model, sizeof(runtime->model)) ||
      !read_property("ro.build.fingerprint", runtime->fingerprint, sizeof(runtime->fingerprint)) ||
      !read_property("ro.build.version.incremental", runtime->incremental, sizeof(runtime->incremental))) {
    set_error(error, error_size, "required build properties are unavailable");
    return 0;
  }
  struct utsname uts;
  if (uname(&uts)) {
    set_error(error, error_size, "uname failed: %s", strerror(errno));
    return 0;
  }
  snprintf(runtime->kernel_release, sizeof(runtime->kernel_release), "%s", uts.release);
  snprintf(runtime->machine, sizeof(runtime->machine), "%s", uts.machine);
  return 1;
}

static int value_matches(const char *expected, const char *actual) {
  return !strcmp(expected, "*") || !strcmp(expected, actual);
}

static int profile_matches(const struct kai_profile *profile, const struct kai_runtime *runtime) {
  return !strcmp(profile->match_product, runtime->product) && value_matches(profile->match_model, runtime->model) &&
         !strcmp(profile->match_fingerprint, runtime->fingerprint) &&
         !strcmp(profile->match_incremental, runtime->incremental) &&
         !strcmp(profile->match_kernel_release, runtime->kernel_release) &&
         !strcmp(profile->match_machine, runtime->machine);
}

static int ends_with_conf(const char *name) {
  size_t length = strlen(name);
  return length > 5 && !strcmp(name + length - 5, ".conf");
}

int kai_profile_select(const char *directory, const char *explicit_path, const struct kai_runtime *runtime,
                       struct kai_profile *profile, char *selected_path, size_t selected_path_size, char *error,
                       size_t error_size) {
  if (explicit_path) {
    if (!parse_profile(explicit_path, profile, error, error_size))
      return 0;
    if (!profile_matches(profile, runtime)) {
      set_error(error, error_size, "profile %s does not match this device", explicit_path);
      return 0;
    }
    snprintf(selected_path, selected_path_size, "%s", explicit_path);
    return 1;
  }

  DIR *dir = opendir(directory);
  if (!dir) {
    set_error(error, error_size, "no profile directory (%s) and no --profile FILE given", directory);
    return 0;
  }
  unsigned matches = 0;
  struct dirent *entry;
  while ((entry = readdir(dir))) {
    if (entry->d_name[0] == '.' || !ends_with_conf(entry->d_name))
      continue;
    char path[1024];
    int length = snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
    if (length < 0 || (size_t)length >= sizeof(path)) {
      set_error(error, error_size, "profile path is too long");
      closedir(dir);
      return 0;
    }
    struct kai_profile candidate;
    if (!parse_profile(path, &candidate, error, error_size)) {
      closedir(dir);
      return 0;
    }
    if (!profile_matches(&candidate, runtime))
      continue;
    matches++;
    *profile = candidate;
    snprintf(selected_path, selected_path_size, "%s", path);
  }
  closedir(dir);
  if (matches == 1)
    return 1;
  if (matches > 1) {
    set_error(error, error_size, "%u profiles in %s match this device, refusing ambiguity", matches, directory);
    return 0;
  }
  set_error(error, error_size, "no profile in %s matches this device", directory);
  return 0;
}

void kai_profile_print(const struct kai_profile *profile, const char *selected_path) {
  printf("kai_root %s (%s) profile=%s\n", profile->target, profile->exploit_path, selected_path);
  fflush(stdout);
}
