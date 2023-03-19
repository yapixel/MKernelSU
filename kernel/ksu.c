#include "linux/fs.h"
#include "linux/module.h"
#include "linux/workqueue.h"

#include "allowlist.h"
#include "arch.h"
#include "core_hook.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "uid_observer.h"

static struct workqueue_struct *ksu_workqueue;

bool ksu_queue_work(struct work_struct *work)
{
	return queue_work(ksu_workqueue, work);
}

extern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
					void *argv, void *envp, int *flags);

extern int ksu_handle_execveat_ksud(int *fd, struct filename **filename_ptr,
				    void *argv, void *envp, int *flags);

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
			void *envp, int *flags)
{
	ksu_handle_execveat_ksud(fd, filename_ptr, argv, envp, flags);
	return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp,
					    flags);
}

extern void ksu_enable_sucompat();
extern void ksu_enable_ksud();

char ksu_random_path[64];

// get random string
static void get_random_string(char *buf, int len)
{
	static char *hex = "0123456789abcdef";
	unsigned char byte;
	int i;
	for (i = 0; i < len; i++) {
		get_random_bytes(&byte, 1);
		buf[i] = hex[byte % 16];
	}
}

extern void init_sucompat_path(void);

int __init kernelsu_init(void)
{
#ifdef CONFIG_KSU_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running DEBUG version of KernelSU       **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif

	ksu_core_init();

	ksu_workqueue = alloc_workqueue("kernelsu_work_queue", 0, 0);

	ksu_allowlist_init();

	ksu_uid_observer_init();

#ifdef CONFIG_KPROBES
	ksu_enable_sucompat();
	ksu_enable_ksud();
#else
#warning("KPROBES is disabled, KernelSU may not work, please check https://kernelsu.org/guide/how-to-integrate-for-non-gki.html")
#endif

	char buf[64];
	get_random_string(buf, 32);
	snprintf(ksu_random_path, sizeof(ksu_random_path), "/dev/ksu_%s", buf);
	pr_info("ksu_random_path: %s\n", ksu_random_path);
	init_sucompat_path();

	return 0;
}

void kernelsu_exit(void)
{
	ksu_allowlist_exit();

	ksu_uid_observer_exit();

	destroy_workqueue(ksu_workqueue);

	ksu_core_exit();
}

module_init(kernelsu_init);
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
