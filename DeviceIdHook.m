// iokit_logger.c
#include <stdio.h>
#include <dlfcn.h>
#include <CoreFoundation/CoreFoundation.h>
#include "fishhook.h"

// IOKit tipleri (header'a bağımlı olmamak için minimal tanım)
typedef unsigned int io_registry_entry_t;
typedef unsigned int IOOptionBits;

static CFTypeRef (*orig_IORegistryEntryCreateCFProperty)(
    io_registry_entry_t entry, CFStringRef key,
    CFAllocatorRef allocator, IOOptionBits options);

static void log_cfstring(const char *prefix, CFStringRef s) {
    if (!s) { fprintf(stderr, "%s(null)\n", prefix); return; }
    char buf[512];
    if (CFStringGetCString(s, buf, sizeof(buf), kCFStringEncodingUTF8))
        fprintf(stderr, "%s%s\n", prefix, buf);
    else
        fprintf(stderr, "%s<non-utf8>\n", prefix);
}

static CFTypeRef my_IORegistryEntryCreateCFProperty(
    io_registry_entry_t entry, CFStringRef key,
    CFAllocatorRef allocator, IOOptionBits options) {

    CFTypeRef result = orig_IORegistryEntryCreateCFProperty(
        entry, key, allocator, options);

    log_cfstring("[IOKit] property requested: ", key);

    if (result && CFGetTypeID(result) == CFStringGetTypeID()) {
        log_cfstring("[IOKit]   -> value: ", (CFStringRef)result);
    } else if (result) {
        fprintf(stderr, "[IOKit]   -> value: <non-string CFType>\n");
    } else {
        fprintf(stderr, "[IOKit]   -> value: (null)\n");
    }
    return result;
}

__attribute__((constructor))
static void init(void) {
    fprintf(stderr, "[IOKit] logger dylib loaded\n");
    rebind_symbols((struct rebinding[1]){
        {"IORegistryEntryCreateCFProperty",
         my_IORegistryEntryCreateCFProperty,
         (void *)&orig_IORegistryEntryCreateCFProperty}
    }, 1);
}
