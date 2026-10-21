#ifndef KAI_PROFILE_H
#define KAI_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#define KAI_PROFILE_STRING 256u

struct kai_runtime {
  char product[KAI_PROFILE_STRING];
  char model[KAI_PROFILE_STRING];
  char fingerprint[KAI_PROFILE_STRING];
  char incremental[KAI_PROFILE_STRING];
  char kernel_release[KAI_PROFILE_STRING];
  char machine[KAI_PROFILE_STRING];
};

struct kai_profile {
  char target[KAI_PROFILE_STRING];

  char match_product[KAI_PROFILE_STRING];
  char match_model[KAI_PROFILE_STRING];
  char match_fingerprint[KAI_PROFILE_STRING];
  char match_incremental[KAI_PROFILE_STRING];
  char match_kernel_release[KAI_PROFILE_STRING];
  char match_machine[KAI_PROFILE_STRING];

  char exploit_path[KAI_PROFILE_STRING];
  uint32_t waiter_core;
  uint32_t consumer_core;
  uint32_t consumer_delay_us;

  uint32_t init_task;
  uint32_t pi_task;
  uint32_t ashmem_fops;
  uint32_t ashmem_misc_fops;
  uint32_t ashmem_open;
  uint32_t ashmem_release;
  uint32_t ashmem_ioctl;
  uint32_t ashmem_mmap;
  uint32_t configfs_read_file;
  uint32_t configfs_write_file;

  uint32_t init_cred; // 0 disables the caps stage
  uint32_t selinux_enforcing; // 0 disables the permissive stage

  uint32_t task_tasks_off;
  uint32_t task_real_cred_off;
  uint32_t task_cred_off;
  uint32_t task_comm_off;

  uint32_t kernel_image_base;
  uint32_t kernel_size;
};

int kai_runtime_read(struct kai_runtime *runtime, char *error, size_t error_size);

int kai_profile_select(const char *directory, const char *explicit_path, const struct kai_runtime *runtime,
                       struct kai_profile *profile, char *selected_path, size_t selected_path_size, char *error,
                       size_t error_size);

void kai_profile_print(const struct kai_profile *profile, const char *selected_path);

#endif
