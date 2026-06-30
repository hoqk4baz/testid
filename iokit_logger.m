// iokit_logger.m
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import "fishhook.h"

typedef int kern_return_t;

static NSMutableString *gLogBuffer;
static UITextView *gLogView;
static UIWindow *gWindow;

static NSString * const kTargetAccount = @"lm_new_device_deviceIdentifier";

static void appendLog(NSString *line) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gLogBuffer) gLogBuffer = [NSMutableString string];
        [gLogBuffer appendString:line];
        [gLogBuffer appendString:@"\n"];
        gLogView.text = gLogBuffer;
    });
}

// NSData -> okunabilir döküm. bplist ise decode eder.
static NSString *describeData(NSData *d) {
    if (!d) return @"(no-data)";

    if (d.length >= 8) {
        const unsigned char *b = d.bytes;
        if (b[0]==0x62 && b[1]==0x70 && b[2]==0x6c && b[3]==0x69 &&
            b[4]==0x73 && b[5]==0x74) {                       // "bplist"
            NSError *err = nil;
            id plist = [NSPropertyListSerialization
                propertyListWithData:d options:NSPropertyListImmutable
                              format:NULL error:&err];
            if (plist) {
                NSString *desc = [plist description];
                NSString *un = @"";
                @try {
                    id obj = [NSKeyedUnarchiver unarchiveObjectWithData:d];
                    if (obj) un = [NSString stringWithFormat:@"\n  unarchived=%@", obj];
                } @catch (__unused NSException *e) {}
                return [NSString stringWithFormat:@" bplist len=%lu\n  plist=%@%@",
                        (unsigned long)d.length, desc, un];
            }
        }
    }

    NSString *utf8 = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (utf8) return [NSString stringWithFormat:@" utf8=%@", utf8];

    const unsigned char *bb = d.bytes;
    NSMutableString *hex = [NSMutableString string];
    for (NSUInteger i = 0; i < d.length; i++) [hex appendFormat:@"%02x", bb[i]];
    NSString *b64 = [d base64EncodedStringWithOptions:0];
    return [NSString stringWithFormat:@" len=%lu\n  hex=%@\n  b64=%@",
            (unsigned long)d.length, hex, b64];
}

#pragma mark - keychain hooks (sadece hedef anahtar)

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus s = orig_SecItemCopyMatching(query, result);
    CFTypeRef acct = query ? CFDictionaryGetValue(query, kSecAttrAccount) : NULL;
    if (acct && CFGetTypeID(acct) == CFStringGetTypeID()) {
        NSString *a = (__bridge NSString *)acct;
        if ([a isEqualToString:kTargetAccount]) {
            NSString *val = @" (value döndürülmedi)";
            if (s == 0 && result && *result &&
                CFGetTypeID(*result) == CFDataGetTypeID()) {
                val = describeData((__bridge NSData *)*result);
            }
            appendLog([NSString stringWithFormat:@"[KC-read] %@ status=%d%@", a, (int)s, val]);
        }
    }
    return s;
}

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus my_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    OSStatus s = orig_SecItemAdd(attributes, result);
    CFTypeRef acct = attributes ? CFDictionaryGetValue(attributes, kSecAttrAccount) : NULL;
    if (acct && CFGetTypeID(acct) == CFStringGetTypeID()) {
        NSString *a = (__bridge NSString *)acct;
        if ([a isEqualToString:kTargetAccount]) {
            CFTypeRef data = CFDictionaryGetValue(attributes, kSecValueData);
            NSString *val = (data && CFGetTypeID(data) == CFDataGetTypeID())
                ? describeData((__bridge NSData *)data) : @" (no-data)";
            appendLog([NSString stringWithFormat:@"[KC-WRITE] %@ status=%d%@", a, (int)s, val]);
        }
    }
    return s;
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    OSStatus s = orig_SecItemUpdate(query, attributesToUpdate);
    CFTypeRef acct = query ? CFDictionaryGetValue(query, kSecAttrAccount) : NULL;
    if (acct && CFGetTypeID(acct) == CFStringGetTypeID()) {
        NSString *a = (__bridge NSString *)acct;
        if ([a isEqualToString:kTargetAccount]) {
            CFTypeRef data = CFDictionaryGetValue(attributesToUpdate, kSecValueData);
            NSString *val = (data && CFGetTypeID(data) == CFDataGetTypeID())
                ? describeData((__bridge NSData *)data) : @" (no-data)";
            appendLog([NSString stringWithFormat:@"[KC-UPDATE] %@ status=%d%@", a, (int)s, val]);
        }
    }
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
    CGFloat h = b.size.height * 0.40;

    gLogView = [[UITextView alloc] initWithFrame:
        CGRectMake(0, b.size.height - h, b.size.width, h)];
    gLogView.editable = NO;
    gLogView.selectable = YES;
    gLogView.backgroundColor = [UIColor colorWithWhite:0 alpha:0.85];
    gLogView.textColor = UIColor.greenColor;
    gLogView.font = [UIFont fontWithName:@"Menlo" size:10];
    gLogView.text = gLogBuffer ?: @"[hazır] lm_new_device_deviceIdentifier izleniyor\n";
    [vc.view addSubview:gLogView];

    UIButton *toggleBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    toggleBtn.frame = CGRectMake(10, b.size.height - h - 36, 80, 30);
    [toggleBtn setTitle:@"Gizle/Aç" forState:UIControlStateNormal];
    toggleBtn.backgroundColor = [UIColor colorWithWhite:0 alpha:0.85];
    [toggleBtn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [toggleBtn addTarget:IOKitLogOverlay.class action:@selector(toggleTapped)
        forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:toggleBtn];

    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(b.size.width - 90, b.size.height - h - 36, 80, 30);
    [copyBtn setTitle:@"Kopyala" forState:UIControlStateNormal];
    copyBtn.backgroundColor = [UIColor colorWithWhite:0 alpha:0.85];
    [copyBtn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [copyBtn addTarget:IOKitLogOverlay.class action:@selector(copyTapped)
        forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:copyBtn];

    gWindow.hidden = NO;
}

#pragma mark - Constructor

__attribute__((constructor))
static void init_logger(void) {
    rebind_symbols((struct rebinding[3]){
        {"SecItemCopyMatching",
         my_SecItemCopyMatching,
         (void *)&orig_SecItemCopyMatching},
        {"SecItemAdd",
         my_SecItemAdd,
         (void *)&orig_SecItemAdd},
        {"SecItemUpdate",
         my_SecItemUpdate,
         (void *)&orig_SecItemUpdate}
    }, 3);

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{ setupOverlay(); });
}
