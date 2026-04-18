#import <substrate.h>
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#import <Security/SecKey.h>
#import <CommonCrypto/CommonCryptor.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <time.h>
#import <stdio.h>
#import <unistd.h>
#import <stdlib.h>
#import <sys/stat.h>
#import <TargetConditionals.h>
#import <sys/param.h>
#import <sys/mount.h>
#include "dobby.h"

// ============================================================================
// [1] Obfuscation helpers (ROT13)
// ============================================================================
static inline void obfuscate_str(char *s) {
    while (*s) {
        if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z')) {
            if ((*s >= 'a' && *s <= 'm') || (*s >= 'A' && *s <= 'M'))
                *s += 13;
            else
                *s -= 13;
        }
        s++;
    }
}

static inline void junk_code(void) {
    volatile int a = rand() % 100;
    volatile int b = rand() % 100;
    volatile int c = a * b + a - b;
    (void)c;
}

// ============================================================================
// [2] Original function pointers
// ============================================================================
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
static void* (*orig_dlopen)(const char *, int);
static void* (*orig_dlsym)(void *, const char *);
static int (*orig_task_for_pid)(mach_port_t, int, mach_port_t *);
static int (*orig_vm_read_overwrite)(vm_map_t, vm_address_t, vm_size_t, vm_address_t, vm_size_t *);
static int (*orig_vm_write)(vm_map_t, vm_address_t, vm_offset_t, mach_msg_type_number_t);
static int (*orig_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t);
static int (*orig_mach_vm_protect)(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);

static SecKeyRef (*orig_SecKeyCreateRandomKey)(CFDictionaryRef, CFErrorRef *);
static SecKeyRef (*orig_SecKeyCopyPublicKey)(SecKeyRef);
static CFDataRef (*orig_SecKeyCreateSignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef *);
static Boolean (*orig_SecKeyVerifySignature)(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFDataRef, CFErrorRef *);

static CCCryptorStatus (*orig_CCCrypt)(CCOperation, CCAlgorithm, CCOptions, const void *, size_t, const void *, const void *, size_t, void *, size_t, size_t *);

static int (*orig_RSA_verify)(int, const unsigned char *, unsigned int, const unsigned char *, unsigned int, RSA *);
static int (*orig_RSA_sign)(int, const unsigned char *, unsigned int, unsigned char *, unsigned int *, RSA *);
static int (*orig_EVP_PKEY_verify)(EVP_PKEY_CTX *, const unsigned char *, size_t, const unsigned char *, size_t);
static int (*orig_X509_verify_cert)(X509_STORE_CTX *);
static int (*orig_X509_check_private_key)(X509 *, EVP_PKEY *);
static EVP_PKEY* (*orig_PEM_read_bio_PrivateKey)(BIO *, EVP_PKEY **, pem_password_cb *, void *);
static int (*orig_SSL_CTX_use_PrivateKey_file)(SSL_CTX *, const char *, int);
static int (*orig_SSL_CTX_check_private_key)(SSL_CTX *);
static int (*orig_SSL_CTX_load_verify_locations)(SSL_CTX *, const char *, const char *);

// ============================================================================
// [3] Replacement functions
// ============================================================================
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
    char buf[256];
    strncpy(buf, name, sizeof(buf));
    obfuscate_str(buf);
    if (strstr(buf, "qroht") || strstr(buf, "xrea.cebp")) {
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
    char buf[256];
    strncpy(buf, symbol, sizeof(buf));
    obfuscate_str(buf);
    if (strstr(buf, "cgenpr") || strstr(buf, "flfpby") || strstr(buf, "gnfx_sbe_cvq") || strstr(buf, "iz_ernq")) {
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

static int my_mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_protection) {
    junk_code();
    return orig_mach_vm_protect ? orig_mach_vm_protect(target_task, address, size, set_max, new_protection) : KERN_SUCCESS;
}

static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    junk_code();
    return errSecItemNotFound;
}

static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    junk_code();
    return errSecDuplicateItem;
}

static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    junk_code();
    return errSecItemNotFound;
}

static OSStatus my_SecItemDelete(CFDictionaryRef query) {
    junk_code();
    return errSecSuccess;
}

static SecKeyRef my_SecKeyCreateRandomKey(CFDictionaryRef parameters, CFErrorRef *error) {
    junk_code();
    return NULL;
}

static SecKeyRef my_SecKeyCopyPublicKey(SecKeyRef key) {
    junk_code();
    return NULL;
}

static CFDataRef my_SecKeyCreateSignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFErrorRef *error) {
    junk_code();
    return CFDataCreate(NULL, (const UInt8*)"fake_signature", 14);
}

static Boolean my_SecKeyVerifySignature(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef dataToSign, CFDataRef signature, CFErrorRef *error) {
    junk_code();
    return true;
}

static CCCryptorStatus my_CCCrypt(CCOperation op, CCAlgorithm alg, CCOptions options, const void *key, size_t keyLength, const void *iv, const void *dataIn, size_t dataInLength, void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    junk_code();
    if (dataOut && dataOutMoved) {
        memcpy(dataOut, dataIn, dataInLength);
        *dataOutMoved = dataInLength;
        return kCCSuccess;
    }
    return kCCSuccess;
}

static int my_RSA_verify(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sig, unsigned int sig_len, RSA *rsa) {
    junk_code();
    return 1;
}

static int my_RSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sig, unsigned int *sig_len, RSA *rsa) {
    junk_code();
    return 1;
}

static int my_EVP_PKEY_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t sig_len, const unsigned char *tbs, size_t tbs_len) {
    junk_code();
    return 1;
}

static int my_X509_verify_cert(X509_STORE_CTX *ctx) {
    junk_code();
    return 1;
}

static int my_X509_check_private_key(X509 *x509, EVP_PKEY *pkey) {
    junk_code();
    return 1;
}

static EVP_PKEY* my_PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) {
    junk_code();
    return NULL;
}

static int my_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) {
    junk_code();
    return 1;
}

static int my_SSL_CTX_check_private_key(SSL_CTX *ctx) {
    junk_code();
    return 1;
}

static int my_SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath) {
    junk_code();
    return 1;
}

// ============================================================================
// [4] Stealth hook (with error checking)
// ============================================================================
static void stealth_hook(const char *obf_name, void *replacement, void **original) {
    char real_name[256];
    strncpy(real_name, obf_name, sizeof(real_name));
    obfuscate_str(real_name);
    void *sym = dlsym(RTLD_DEFAULT, real_name);
    if (sym) {
        DobbyHook(sym, replacement, original);
    }
}

static void hook_all_functions() {
    stealth_hook("cgenpr", (void*)my_ptrace, (void**)&orig_ptrace);
    stealth_hook("flfpby", (void*)my_sysctl, (void**)&orig_sysctl);
    stealth_hook("flfpbyolanzr", (void*)my_sysctlbyname, (void**)&orig_sysctlbyname);
    stealth_hook("qybcra", (void*)my_dlopen, (void**)&orig_dlopen);
    stealth_hook("qyflz", (void*)my_dlsym, (void**)&orig_dlsym);
    stealth_hook("gnfx_sbe_cvq", (void*)my_task_for_pid, (void**)&orig_task_for_pid);
    stealth_hook("iz_ernq_birejevgr", (void*)my_vm_read_overwrite, (void**)&orig_vm_read_overwrite);
    stealth_hook("iz_jevgr", (void*)my_vm_write, (void**)&orig_vm_write);
    stealth_hook("iz_cebgrpg", (void*)my_vm_protect, (void**)&orig_vm_protect);
    stealth_hook("znpu_iz_cebgrpg", (void*)my_mach_vm_protect, (void**)&orig_mach_vm_protect);

    stealth_hook("FrpVgrzPbclZngpuvat", (void*)my_SecItemCopyMatching, (void**)&orig_SecItemCopyMatching);
    stealth_hook("FrpVgrzNqq", (void*)my_SecItemAdd, (void**)&orig_SecItemAdd);
    stealth_hook("FrpVgrzHcqngr", (void*)my_SecItemUpdate, (void**)&orig_SecItemUpdate);
    stealth_hook("FrpVgrzQryrgr", (void*)my_SecItemDelete, (void**)&orig_SecItemDelete);

    stealth_hook("FrpXrlPerngrEnaqbzXrl", (void*)my_SecKeyCreateRandomKey, (void**)&orig_SecKeyCreateRandomKey);
    stealth_hook("FrpXrlPbclChoyvpXrl", (void*)my_SecKeyCopyPublicKey, (void**)&orig_SecKeyCopyPublicKey);
    stealth_hook("FrpXrlPerngrFvtangher", (void*)my_SecKeyCreateSignature, (void**)&orig_SecKeyCreateSignature);
    stealth_hook("FrpXrlIrevslFvtangher", (void*)my_SecKeyVerifySignature, (void**)&orig_SecKeyVerifySignature);

    stealth_hook("PPPelcg", (void*)my_CCCrypt, (void**)&orig_CCCrypt);

    stealth_hook("ENF_irevsl", (void*)my_RSA_verify, (void**)&orig_RSA_verify);
    stealth_hook("ENF_fvta", (void*)my_RSA_sign, (void**)&orig_RSA_sign);
    stealth_hook("RUC_XRL_irevsl", (void*)my_EVP_PKEY_verify, (void**)&orig_EVP_PKEY_verify);
    stealth_hook("K509_irevsl_preg", (void*)my_X509_verify_cert, (void**)&orig_X509_verify_cert);
    stealth_hook("K509_purpx_cevingr_xrl", (void*)my_X509_check_private_key, (void**)&orig_X509_check_private_key);
    stealth_hook("CRZ_ernq_ovb_CevngrXrl", (void*)my_PEM_read_bio_PrivateKey, (void**)&orig_PEM_read_bio_PrivateKey);
    stealth_hook("FFY_PGK_hfr_CevngrXrl_svyr", (void*)my_SSL_CTX_use_PrivateKey_file, (void**)&orig_SSL_CTX_use_PrivateKey_file);
    stealth_hook("FFY_PGK_purpx_cevingr_xrl", (void*)my_SSL_CTX_check_private_key, (void**)&orig_SSL_CTX_check_private_key);
    stealth_hook("FFY_PGK_ybnq_irevsl_ybpngvbaf", (void*)my_SSL_CTX_load_verify_locations, (void**)&orig_SSL_CTX_load_verify_locations);
}

// ============================================================================
// [5] Logos %ctor (replaces __attribute__((constructor)))
// ============================================================================
%ctor {
    srand((unsigned int)time(NULL));
    // Security checks يمكن تفعيلها حسب الحاجة
    hook_all_functions();

    %hook UIDevice
    - (NSUUID *)identifierForVendor {
        return [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
    }
    %end

    %hook LAContext
    - (void)evaluatePolicy:(LAPolicy)policy localizedReason:(NSString *)localizedReason reply:(void (^)(BOOL, NSError *))reply {
        reply(YES, nil);
    }
    - (BOOL)canEvaluatePolicy:(LAPolicy)policy error:(NSError **)error {
        return YES;
    }
    %end
}
