// iokit_logger.m
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import "fishhook.h"

typedef unsigned int io_registry_entry_t;
typedef unsigned int IOOptionBits;
typedef int kern_return_t;

static NSMutableString *gLogBuffer;
static UITextView *gLogView;
static UIWindow *gWindow;

static void appendLog(NSString *line) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gLogBuffer) gLogBuffer = [NSMutableString string];
        [gLogBuffer appendString:line];
        [gLogBuffer appendString:@"\n"];
        gLogView.text = gLogBuffer;
    });
}

#pragma mark - IOKit hooks

static CFTypeRef (*orig_IORegistryEntryCreateCFProperty)(
    io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits);
static CFTypeRef my_IORegistryEntryCreateCFProperty(
    io_registry_entry_t entry, CFStringRef key,
    CFAllocatorRef allocator, IOOptionBits options) {
    CFTypeRef result = orig_IORegistryEntryCreateCFProperty(entry, key, allocator, options);
    NSString *k = key ? (__bridge NSString *)key : @"(null)";
    NSString *v = (result && CFGetTypeID(result) == CFStringGetTypeID())
        ? (__bridge NSString *)result : (result ? @"<non-string>" : @"(null)");
    appendLog([NSString stringWithFormat:@"[Create] %@ = %@", k, v]);
    return result;
}

static CFTypeRef (*orig_IORegistryEntrySearchCFProperty)(
    io_registry_entry_t, const char *, CFStringRef, CFAllocatorRef, IOOptionBits);
static CFTypeRef my_IORegistryEntrySearchCFProperty(
    io_registry_entry_t entry, const char *plane, CFStringRef key,
    CFAllocatorRef allocator, IOOptionBits options) {
    CFTypeRef result = orig_IORegistryEntrySearchCFProperty(entry, plane, key, allocator, options);
    NSString *k = key ? (__bridge NSString *)key : @"(null)";
    NSString *v = (result && CFGetTypeID(result) == CFStringGetTypeID())
        ? (__bridge NSString *)result : (result ? @"<non-string>" : @"(null)");
    appendLog([NSString stringWithFormat:@"[Search] %@ = %@", k, v]);
    return result;
}

static kern_return_t (*orig_IORegistryEntryCreateCFProperties)(
    io_registry_entry_t, CFMutableDictionaryRef *, CFAllocatorRef, IOOptionBits);
static kern_return_t my_IORegistryEntryCreateCFProperties(
    io_registry_entry_t entry, CFMutableDictionaryRef *props,
    CFAllocatorRef allocator, IOOptionBits options) {
    kern_return_t r = orig_IORegistryEntryCreateCFProperties(entry, props, allocator, options);
    if (r == 0 && props && *props) {
        for (NSString *key in @[@"IOPlatformSerialNumber", @"IOPlatformUUID"]) {
            CFTypeRef val = CFDictionaryGetValue(*props, (__bridge CFStringRef)key);
            if (val && CFGetTypeID(val) == CFStringGetTypeID())
                appendLog([NSString stringWithFormat:@"[Props] %@ = %@",
                    key, (__bridge NSString *)val]);
        }
    }
    return r;
}

#pragma mark - identifierForVendor & keychain hooks

static NSUUID *(*orig_idfv)(id, SEL);
static NSUUID *my_idfv(id self, SEL _cmd) {
    NSUUID *r = orig_idfv(self, _cmd);
    appendLog([NSString stringWithFormat:@"[IDFV] %@", r.UUIDString]);
    return r;
}

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus s = orig_SecItemCopyMatching(query, result);
    CFTypeRef acct = query ? CFDictionaryGetValue(query, kSecAttrAccount) : NULL;
    NSString *a = (acct && CFGetTypeID(acct) == CFStringGetTypeID())
        ? (__bridge NSString *)acct : @"(?)";
    appendLog([NSString stringWithFormat:@"[Keychain] read account=%@ status=%d", a, (int)s]);
    return s;
}

#pragma mark - Passthrough window

@interface PassthroughWindow : UIWindow @end
@implementation PassthroughWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    if (hit == self.rootViewController.view) return nil;
    return hit;
}
@end

#pragma mark - Overlay UI

@interface IOKitLogOverlay : NSObject
+ (void)copyTapped;
+ (void)toggleTapped;
@end
@implementation IOKitLogOverlay
+ (void)copyTapped { [UIPasteboard generalPasteboard].string = gLogBuffer ?: @""; }
+ (void)toggleTapped { gLogView.hidden = !gLogView.hidden; }
@end

static void setupOverlay(void) {
    UIWindowScene *scene = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:UIWindowScene.class] &&
            s.activationState == UISceneActivationStateForegroundActive) {
            scene = (UIWindowScene *)s; break;
        }
    }
    if (!scene) return;

    gWindow = [[PassthroughWindow alloc] initWithWindowScene:scene];
    gWindow.windowLevel = UIWindowLevelAlert + 1;
    gWindow.backgroundColor = UIColor.clearColor;
    gWindow.frame = scene.coordinateSpace.bounds;

    UIViewController *vc = [UIViewController new];
    gWindow.rootViewController = vc;
    vc.view.backgroundColor = UIColor.clearColor;

    CGRect b = vc.view.bounds;
    CGFloat h = b.size.height * 0.35;

    gLogView = [[UITextView alloc] initWithFrame:
        CGRectMake(0, b.size.height - h, b.size.width, h)];
    gLogView.editable = NO;
    gLogView.selectable = YES;
    gLogView.backgroundColor = [UIColor colorWithWhite:0 alpha:0.8];
    gLogView.textColor = UIColor.greenColor;
    gLogView.font = [UIFont fontWithName:@"Menlo" size:11];
    gLogView.text = gLogBuffer ?: @"[IOKit] hazır\n";
    [vc.view addSubview:gLogView];

    UIButton *toggleBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    toggleBtn.frame = CGRectMake(10, b.size.height - h - 36, 80, 30);
    [toggleBtn setTitle:@"Gizle/Aç" forState:UIControlStateNormal];
    toggleBtn.backgroundColor = [UIColor colorWithWhite:0 alpha:0.8];
    [toggleBtn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [toggleBtn addTarget:IOKitLogOverlay.class action:@selector(toggleTapped)
        forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:toggleBtn];

    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(b.size.width - 90, b.size.height - h - 36, 80, 30);
    [copyBtn setTitle:@"Kopyala" forState:UIControlStateNormal];
    copyBtn.backgroundColor = [UIColor colorWithWhite:0 alpha:0.8];
    [copyBtn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [copyBtn addTarget:IOKitLogOverlay.class action:@selector(copyTapped)
        forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:copyBtn];

    gWindow.hidden = NO;
}

#pragma mark - Constructor

__attribute__((constructor))
static void init_logger(void) {
    rebind_symbols((struct rebinding[4]){
        {"IORegistryEntryCreateCFProperty",
         my_IORegistryEntryCreateCFProperty,
         (void *)&orig_IORegistryEntryCreateCFProperty},
        {"IORegistryEntrySearchCFProperty",
         my_IORegistryEntrySearchCFProperty,
         (void *)&orig_IORegistryEntrySearchCFProperty},
        {"IORegistryEntryCreateCFProperties",
         my_IORegistryEntryCreateCFProperties,
         (void *)&orig_IORegistryEntryCreateCFProperties},
        {"SecItemCopyMatching",
         my_SecItemCopyMatching,
         (void *)&orig_SecItemCopyMatching}
    }, 4);

    Method m = class_getInstanceMethod(UIDevice.class, @selector(identifierForVendor));
    if (m) {
        orig_idfv = (void *)method_getImplementation(m);
        method_setImplementation(m, (IMP)my_idfv);
    }

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{ setupOverlay(); });
}
