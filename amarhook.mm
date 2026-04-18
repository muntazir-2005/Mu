#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <unistd.h>
#import <stdlib.h>
#import <TargetConditionals.h>
#import "fishhook.h"

// تعريف PT_DENY_ATTACH يدويًا (غير موجود في iOS SDK)
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

// ================== دوال التمويه ==================
static inline void junk_code(void) {
    volatile int a = rand() % 100;
    volatile int b = rand() % 100;
    volatile int c = a * b + a - b;
    (void)c;
}

// ================== مؤشرات الدوال الأصلية ==================
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static void* (*orig_dlopen)(const char *, int);
static void* (*orig_dlsym)(void *, const char *);
static int (*orig_task_for_pid)(mach_port_t, int, mach_port_t *);
static int (*orig_vm_read_overwrite)(vm_map_t, vm_address_t, vm_size_t, vm_address_t, vm_size_t *);
static int (*orig_vm_write)(vm_map_t, vm_address_t, vm_offset_t, mach_msg_type_number_t);
static int (*orig_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);

// ================== الدوال المُستبدَلة ==================
static int my_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    junk_code();
    if (request == PT_DENY_ATTACH) return 0;
    return orig_ptrace ? orig_ptrace(request, pid, addr, data) : 0;
}

static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    junk_code();
    int ret = orig_sysctl ? orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen) : 0;
    if (ret == 0 && oldp && namelen == 4 && name[0] == CTL_KERN && name[1] == KERN_PROC && name[2] == KERN_PROC_PID) {
        struct kinfo_proc *kp = (struct kinfo_proc *)oldp;
        kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return ret;
}

static int my_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    junk_code();
    if (strcmp(name, "kern.proc.pid") == 0 || strcmp(name, "debug") == 0) {
        if (oldp && oldlenp) {
            memset(oldp, 0, *oldlenp);
            return 0;
        }
    }
    return orig_sysctlbyname ? orig_sysctlbyname(name, oldp, oldlenp, newp, newlen) : 0;
}

static void* my_dlopen(const char *path, int mode) {
    junk_code();
    return orig_dlopen ? orig_dlopen(path, mode) : NULL;
}

static void* my_dlsym(void *handle, const char *symbol) {
    junk_code();
    if (strcmp(symbol, "ptrace") == 0 || strcmp(symbol, "sysctl") == 0 || strcmp(symbol, "task_for_pid") == 0) {
        return NULL;
    }
    return orig_dlsym ? orig_dlsym(handle, symbol) : NULL;
}

static int my_task_for_pid(mach_port_t target_tport, int pid, mach_port_t *tn) {
    junk_code();
    return KERN_FAILURE;
}

static int my_vm_read_overwrite(vm_map_t target_task, vm_address_t address, vm_size_t size, vm_address_t data, vm_size_t *outsize) {
    junk_code();
    return KERN_FAILURE;
}

static int my_vm_write(vm_map_t target_task, vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt) {
    junk_code();
    return KERN_FAILURE;
}

static int my_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    junk_code();
    return orig_vm_protect ? orig_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}

// ================== تركيب الخطافات (C functions) ==================
static void hook_c_functions() {
    struct rebinding rebindings[] = {
        {"ptrace", (void*)my_ptrace, (void**)&orig_ptrace},
        {"sysctl", (void*)my_sysctl, (void**)&orig_sysctl},
        {"sysctlbyname", (void*)my_sysctlbyname, (void**)&orig_sysctlbyname},
        {"dlopen", (void*)my_dlopen, (void**)&orig_dlopen},
        {"dlsym", (void*)my_dlsym, (void**)&orig_dlsym},
        {"task_for_pid", (void*)my_task_for_pid, (void**)&orig_task_for_pid},
        {"vm_read_overwrite", (void*)my_vm_read_overwrite, (void**)&orig_vm_read_overwrite},
        {"vm_write", (void*)my_vm_write, (void**)&orig_vm_write},
        {"vm_protect", (void*)my_vm_protect, (void**)&orig_vm_protect}
    };
    rebind_symbols(rebindings, sizeof(rebindings)/sizeof(rebindings[0]));
}

// ================== خطافات Objective-C (Runtime) ==================
static void hook_objc_methods() {
    // UIDevice - identifierForVendor
    Class deviceCls = objc_getClass("UIDevice");
    if (deviceCls) {
        SEL sel = @selector(identifierForVendor);
        Method m = class_getInstanceMethod(deviceCls, sel);
        if (m) {
            IMP newImp = imp_implementationWithBlock(^NSUUID *(id self) {
                return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
            });
            method_setImplementation(m, newImp);
        }
    }

    // LAContext - evaluatePolicy:localizedReason:reply:
    Class laContextCls = objc_getClass("LAContext");
    if (laContextCls) {
        SEL sel = @selector(evaluatePolicy:localizedReason:reply:);
        Method m = class_getInstanceMethod(laContextCls, sel);
        if (m) {
            IMP newImp = imp_implementationWithBlock(^(id self, LAPolicy policy, NSString *reason, void (^reply)(BOOL, NSError *)) {
                reply(YES, nil);
            });
            method_setImplementation(m, newImp);
        }
        sel = @selector(canEvaluatePolicy:error:);
        m = class_getInstanceMethod(laContextCls, sel);
        if (m) {
            IMP newImp = imp_implementationWithBlock(^(id self, LAPolicy policy, NSError **error) {
                return YES;
            });
            method_setImplementation(m, newImp);
        }
    }
}

// ================== Constructor ==================
__attribute__((constructor))
static void init_hook() {
    srand((unsigned int)time(NULL));
    hook_c_functions();
    hook_objc_methods();
}
