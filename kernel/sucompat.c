#include "asm/current.h"
#include "linux/cred.h"
#include "linux/err.h"
#include "linux/fs.h"
#include "linux/kprobes.h"
#include "linux/types.h"
#include "linux/uaccess.h"
#include "linux/version.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include "linux/sched/task_stack.h"
#else
#include "linux/sched.h"
#endif

#include "allowlist.h"
#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

static char real_su_path[128];
static int real_su_path_len = 0;

static void __user *userspace_stack_buffer(const void *d, size_t len)
{
	/* To avoid having to mmap a page in userspace, just write below the stack
   * pointer. */
	char __user *p = (void __user *)current_user_stack_pointer() - len;

	return copy_to_user(p, d, len) ? NULL : p;
}

void init_sucompat_path(void) {
	if (real_su_path_len <= 0 || real_su_path_len >= 128) {
		real_su_path_len = snprintf(real_su_path, sizeof(real_su_path), "%s/bin/su", ksu_random_path);
	}

	if (real_su_path_len <= 0 || real_su_path_len >= 128) {
		pr_err("failed to get real su path, len=", real_su_path_len);
	} else {
		pr_info("real su path(%d): %s", real_su_path_len, real_su_path);
	}
}

static char __user *real_su_user_path(void)
{
	if (real_su_path_len <= 0 || real_su_path_len >= 128) {
		return NULL;
	} else {
		return userspace_stack_buffer(real_su_path, real_su_path_len + 1);
	}
}

int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,
			 int *flags)
{
	struct filename *filename;
	const char su[] = SU_PATH;

	if (!ksu_is_allow_uid(current_uid().val)) {
		return 0;
	}

	filename = getname(*filename_user);

	if (IS_ERR(filename)) {
		return 0;
	}
	if (!memcmp(filename->name, su, sizeof(su))) {
		pr_info("faccessat su->sh!\n");
		*filename_user = real_su_user_path();
	}

	putname(filename);

	return 0;
}

int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
	// const char sh[] = SH_PATH;
	struct filename *filename;
	const char su[] = SU_PATH;

	if (!ksu_is_allow_uid(current_uid().val)) {
		return 0;
	}

	if (!filename_user) {
		return 0;
	}

	filename = getname(*filename_user);

	if (IS_ERR(filename)) {
		return 0;
	}
	if (!memcmp(filename->name, su, sizeof(su))) {
		pr_info("newfstatat su->sh!\n");
		*filename_user = real_su_user_path();
	}

	putname(filename);

	return 0;
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
				 void *argv, void *envp, int *flags)
{
	struct filename *filename;
	const char su[] = SU_PATH;

	if (!filename_ptr)
		return 0;

	filename = *filename_ptr;
	if (IS_ERR(filename)) {
		return 0;
	}

	if (!ksu_is_allow_uid(current_uid().val)) {
		return 0;
	}

	if (!memcmp(filename->name, su, sizeof(su))) {
		pr_info("do_execveat_common su found\n");
		if (real_su_path_len > 0 && real_su_path_len < 128) {
			putname(filename);
			*filename_ptr = getname_kernel(real_su_path);
		}
	}

	return 0;
}

#ifdef CONFIG_KPROBES

static int faccessat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	int *dfd = (int *)PT_REGS_PARM1(regs);
	const char __user **filename_user = (const char **)&PT_REGS_PARM2(regs);
	int *mode = (int *)&PT_REGS_PARM3(regs);
	int *flags = (int *)&PT_REGS_PARM4(regs);

	return ksu_handle_faccessat(dfd, filename_user, mode, flags);
}

static int newfstatat_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	int *dfd = (int *)&PT_REGS_PARM1(regs);
	const char __user **filename_user = (const char **)&PT_REGS_PARM2(regs);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
// static int vfs_statx(int dfd, const char __user *filename, int flags, struct kstat *stat, u32 request_mask)
	int *flags = (int *)&PT_REGS_PARM3(regs);
#else
// int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat,int flag)
	int *flags = (int *)&PT_REGS_PARM4(regs);
#endif

	return ksu_handle_stat(dfd, filename_user, flags);
}

// https://elixir.bootlin.com/linux/v5.10.158/source/fs/exec.c#L1864
static int execve_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	int *fd = (int *)&PT_REGS_PARM1(regs);
	struct filename **filename_ptr =
		(struct filename **)&PT_REGS_PARM2(regs);
	void *argv = (void *)&PT_REGS_PARM3(regs);
	void *envp = (void *)&PT_REGS_PARM4(regs);
	int *flags = (int *)&PT_REGS_PARM5(regs);

	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
					    flags);
}

static struct kprobe faccessat_kp = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	.symbol_name = "do_faccessat",
#else
	.symbol_name = "sys_faccessat",
#endif
	.pre_handler = faccessat_handler_pre,
};

static struct kprobe newfstatat_kp = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	.symbol_name = "vfs_statx",
#else
	.symbol_name = "vfs_fstatat",
#endif
	.pre_handler = newfstatat_handler_pre,
};

static struct kprobe execve_kp = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	.symbol_name = "do_execveat_common",
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
	.symbol_name = "__do_execve_file",
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	.symbol_name = "do_execveat_common",
#endif
	.pre_handler = execve_handler_pre,
};

#endif

// sucompat: permited process can execute 'su' to gain root access.
void ksu_enable_sucompat()
{
#ifdef CONFIG_KPROBES
	int ret;
	ret = register_kprobe(&execve_kp);
	pr_info("sucompat: execve_kp: %d\n", ret);
	ret = register_kprobe(&newfstatat_kp);
	pr_info("sucompat: newfstatat_kp: %d\n", ret);
	ret = register_kprobe(&faccessat_kp);
	pr_info("sucompat: faccessat_kp: %d\n", ret);
#endif
}
