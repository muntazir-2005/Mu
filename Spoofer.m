// =============== User-Space API Spoofer - Professional Edition ===============
// يعمل على macOS بدون جيلبريك (مع صلاحيات مناسبة)
// تقنيات: Dobby + fishhook + Method Swizzling
// تم إصلاح: حلقة الإشعارات، اكتشاف الذات، ptrace الزائدة

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <libproc.h>
#import <sys/ptrace.h>
#import <os/log.h>

#include "dobby.h"
#include "fishhook.h"

// ================================================
// 1. تعريف دوال الاعتراض (API Hooking)
// ================================================

// 1.1 sysctl - تصفية قوائم العمليات لإخفاء العملية الحالية
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int my_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int ret = orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    
    if (name[0] == CTL_KERN && name[1] == KERN_PROC_ALL && oldp != NULL && ret == 0) {
        struct kinfo_proc *procs = (struct kinfo_proc *)oldp;
        size_t count = *oldlenp / sizeof(struct kinfo_proc);
        pid_t my_pid = getpid();
        
        size_t new_count = 0;
        for (size_t i = 0; i < count; i++) {
            if (procs[i].kp_proc.p_pid != my_pid) {
                if (new_count != i) procs[new_count] = procs[i];
                new_count++;
            }
        }
        *oldlenp = new_count * sizeof(struct kinfo_proc);
    }
    
    if (name[0] == CTL_KERN && name[1] == KERN_PROC_PID && name[2] == getpid()) {
        errno = ESRCH;
        return -1;
    }
    
    return ret;
}

// 1.2 proc_pidinfo - إخفاء معلومات العملية
static int (*orig_proc_pidinfo)(int, int, uint64_t, void *, int);
static int my_proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize) {
    if (pid == getpid()) {
        errno = ESRCH;
        return 0;
    }
    return orig_proc_pidinfo(pid, flavor, arg, buffer, buffersize);
}

// 1.3 mach_port_allocate - تمرير الطلب (لا نمنع)
static kern_return_t (*orig_mach_port_allocate)(ipc_space_t, mach_port_right_t, mach_port_name_t *);
static kern_return_t my_mach_port_allocate(ipc_space_t task, mach_port_right_t right, mach_port_name_t *name) {
    return orig_mach_port_allocate(task, right, name);
}

// 1.4 fprintf - تعطيل السجلات
static int (*orig_fprintf)(FILE *, const char *, ...);
static int my_fprintf(FILE *stream, const char *format, ...) {
    if (stream == stderr || stream == stdout) return 0;
    va_list args;
    va_start(args, format);
    int ret = vfprintf(stream, format, args);
    va_end(args);
    return ret;
}

// 1.5 os_log_create - تعطيل سجلات النظام
static os_log_t (*orig_os_log_create)(const char *, const char *);
static os_log_t my_os_log_create(const char *subsystem, const char *category) {
    return NULL;
}

// 1.6 LSRegisterURL - منع تسجيل التطبيقات
static OSStatus (*orig_LSRegisterURL)(CFURLRef, Boolean);
static OSStatus my_LSRegisterURL(CFURLRef url, Boolean update) {
    return noErr;
}

// 1.7 _LSCopyAllApplicationURLs - إخفاء التطبيقات المثبتة
static CFArrayRef (*orig_LSCopyAllApplicationURLs)(void);
static CFArrayRef my_LSCopyAllApplicationURLs(void) {
    return CFArrayCreate(NULL, NULL, 0, NULL);
}

// ================================================
// 2. كلاس الإخفاء - Method Swizzling
// ================================================
@interface AppHider : NSObject
- (void)hideAll;
@end

@implementation AppHider {
    NSArray* (*orig_runningApps)(id, SEL);
}

- (void)hideAll {
    // Swizzle NSWorkspace runningApplications
    Method m = class_getInstanceMethod([NSWorkspace class], @selector(runningApplications));
    orig_runningApps = (NSArray*(*)(id, SEL))method_getImplementation(m);
    IMP imp = imp_implementationWithBlock(^NSArray*(id self) {
        NSArray *originalList = orig_runningApps(self, @selector(runningApplications));
        NSMutableArray *filtered = [NSMutableArray array];
        NSArray *forbidden = @[@"Terminal", @"iTerm", @"Activity Monitor", @"Xcode", @"lldb", @"frida"];
        for (NSRunningApplication *app in originalList) {
            BOOL isForbidden = NO;
            for (NSString *name in forbidden) {
                if ([app.localizedName containsString:name] || [app.bundleIdentifier containsString:name]) {
                    isForbidden = YES;
                    break;
                }
            }
            if (!isForbidden) [filtered addObject:app];
        }
        return filtered;
    });
    method_setImplementation(m, imp);
    
    // Hook LaunchServices
    void *p = dlsym(RTLD_DEFAULT, "LSRegisterURL");
    if (p) DobbyHook(p, (void*)my_LSRegisterURL, (void**)&orig_LSRegisterURL);
    p = dlsym(RTLD_DEFAULT, "_LSCopyAllApplicationURLs");
    if (p) DobbyHook(p, (void*)my_LSCopyAllApplicationURLs, (void**)&orig_LSCopyAllApplicationURLs);
}

@end

// ================================================
// 3. كلاس الحماية - Anti-Debug & Anti-Trace
// ================================================
@interface ProcessProtector : NSObject
- (void)protect;
- (BOOL)isDebuggerAttached;
- (BOOL)isBeingTraced;
@end

@implementation ProcessProtector

- (void)protect {
    // منع التصحيح مباشرة
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
    
    // Hook proc_pidinfo
    void *p = dlsym(RTLD_DEFAULT, "proc_pidinfo");
    if (p) DobbyHook(p, (void*)my_proc_pidinfo, (void**)&orig_proc_pidinfo);
    
    // Hook mach_port_allocate (تمرير فقط)
    p = dlsym(RTLD_DEFAULT, "mach_port_allocate");
    if (p) DobbyHook(p, (void*)my_mach_port_allocate, (void**)&orig_mach_port_allocate);
}

- (BOOL)isDebuggerAttached {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    info.kp_proc.p_flag = 0;
    sysctl(mib, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

- (BOOL)isBeingTraced {
    // ✅ تم إزالة فحص DYLD_INSERT_LIBRARIES (كان يسبب اكتشاف الذات)
    return [self isDebuggerAttached];
}

@end

// ================================================
// 4. كلاس تمويه النظام
// ================================================
@interface SystemSpoofer : NSObject
- (void)spoof;
@end

@implementation SystemSpoofer

- (void)spoof {
    Method m = class_getInstanceMethod([NSProcessInfo class], @selector(operatingSystemVersion));
    IMP fake = imp_implementationWithBlock(^NSOperatingSystemVersion {
        return (NSOperatingSystemVersion){15, 0, 0};
    });
    method_setImplementation(m, fake);
    
    m = class_getInstanceMethod([NSProcessInfo class], @selector(operatingSystemVersionString));
    fake = imp_implementationWithBlock(^NSString * {
        return @"Version 15.0 (Build 24A334)";
    });
    method_setImplementation(m, fake);
}

@end

// ================================================
// 5. اعتراض الإشعارات الموزعة (Swizzle بدلاً من Observer)
// ================================================
@interface NotificationInterceptor : NSObject
- (void)start;
@end

@implementation NotificationInterceptor

- (void)start {
    // ✅ Swizzle دالة postNotificationName لمنع الإشعارات المحظورة (لا يوجد حلقة لا نهائية)
    Class centerClass = [NSDistributedNotificationCenter class];
    SEL originalSel = @selector(postNotificationName:object:userInfo:deliverImmediately:);
    Method originalMethod = class_getInstanceMethod(centerClass, originalSel);
    IMP originalImp = method_getImplementation(originalMethod);
    
    IMP newImp = imp_implementationWithBlock(^(id self, NSNotificationName name, id object, NSDictionary *userInfo, BOOL deliverImmediately) {
        NSArray *blocked = @[
            @"com.apple.security.assessment",
            @"com.apple.security.scan",
            @"com.game.anticheat.scan"
        ];
        if ([blocked containsObject:name]) {
            // تجاهل الإشعار تماماً
            return;
        }
        // استدعاء الدالة الأصلية للإشعارات الأخرى
        ((void(*)(id, SEL, NSNotificationName, id, NSDictionary*, BOOL))originalImp)(self, originalSel, name, object, userInfo, deliverImmediately);
    });
    method_setImplementation(originalMethod, newImp);
}

@end

// ================================================
// 6. تفعيل جميع الهوكات عند التحميل
// ================================================
__attribute__((constructor))
static void initHooks() {
    struct rebinding rebinds[] = {
        {"sysctl", (void*)my_sysctl, (void**)&orig_sysctl},
        {"fprintf", (void*)my_fprintf, (void**)&orig_fprintf}
    };
    rebind_symbols(rebinds, sizeof(rebinds)/sizeof(rebinds[0]));
    
    void *p = dlsym(RTLD_DEFAULT, "os_log_create");
    if (p) DobbyHook(p, (void*)my_os_log_create, (void**)&orig_os_log_create);
}

__attribute__((constructor))
static void delayedStart() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [[AppHider new] hideAll];
        [[ProcessProtector new] protect];
        [[SystemSpoofer new] spoof];
        [[NotificationInterceptor new] start];
        
        ProcessProtector *p = [ProcessProtector new];
        if ([p isBeingTraced]) {
            NSLog(@"[SPOOFER] ⚠️ تم اكتشاف مصحح!");
        } else {
            NSLog(@"[SPOOFER] ✅ جميع الحمايات مفعلة");
        }
    });
}
