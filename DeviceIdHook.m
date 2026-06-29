// iokit_logger.m
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import "fishhook.h"

typedef unsigned int io_registry_entry_t;
typedef unsigned int IOOptionBits;

static NSMutableString *gLogBuffer;
static UITextView *gLogView;

static void appendLog(NSString *line) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gLogBuffer) gLogBuffer = [NSMutableString string];
        [gLogBuffer appendString:line];
        [gLogBuffer appendString:@"\n"];
        gLogView.text = gLogBuffer;
    });
}

// --- IOKit hook ---
static CFTypeRef (*orig_IORegistryEntryCreateCFProperty)(
    io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits);

static CFTypeRef my_IORegistryEntryCreateCFProperty(
    io_registry_entry_t entry, CFStringRef key,
    CFAllocatorRef allocator, IOOptionBits options) {

    CFTypeRef result = orig_IORegistryEntryCreateCFProperty(entry, key, allocator, options);

    NSString *k = key ? (__bridge NSString *)key : @"(null)";
    NSString *v = @"(null)";
    if (result && CFGetTypeID(result) == CFStringGetTypeID())
        v = (__bridge NSString *)result;
    else if (result)
        v = @"<non-string CFType>";

    appendLog([NSString stringWithFormat:@"%@ = %@", k, v]);
    return result;
}

// --- In-app overlay ---
@interface IOKitLogOverlay : NSObject
+ (void)copyTapped;
+ (void)toggleTapped;
@end

static UIWindow *gWindow;

@implementation IOKitLogOverlay
+ (void)copyTapped {
    [UIPasteboard generalPasteboard].string = gLogBuffer ?: @"";
}
+ (void)toggleTapped {
    gLogView.hidden = !gLogView.hidden;
}
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

    gWindow = [[UIWindow alloc] initWithWindowScene:scene];
    gWindow.windowLevel = UIWindowLevelAlert + 1;
    gWindow.backgroundColor = UIColor.clearColor;
    gWindow.frame = scene.coordinateSpace.bounds;

    UIViewController *vc = [UIViewController new];
    gWindow.rootViewController = vc;
    // overlay'in arkasındaki uygulamaya dokunmaları geçirmek için:
    vc.view.userInteractionEnabled = YES;
    vc.view.backgroundColor = UIColor.clearColor;

    CGRect b = vc.view.bounds;
    CGFloat h = b.size.height * 0.35;

    gLogView = [[UITextView alloc] initWithFrame:
        CGRectMake(0, b.size.height - h, b.size.width, h)];
    gLogView.editable = NO;
    gLogView.selectable = YES;            // uzun bas -> kopyala
    gLogView.backgroundColor = [UIColor colorWithWhite:0 alpha:0.8];
    gLogView.textColor = UIColor.greenColor;
    gLogView.font = [UIFont fontWithName:@"Menlo" size:11];
    gLogView.text = gLogBuffer ?: @"[IOKit] hazır\n";
    [vc.view addSubview:gLogView];

    UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    copyBtn.frame = CGRectMake(b.size.width - 80, b.size.height - h - 36, 70, 30);
    [copyBtn setTitle:@"Kopyala" forState:UIControlStateNormal];
    copyBtn.backgroundColor = [UIColor colorWithWhite:0 alpha:0.8];
    [copyBtn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [copyBtn addTarget:IOKitLogOverlay.class action:@selector(copyTapped)
        forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:copyBtn];

    UIButton *toggleBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    toggleBtn.frame = CGRectMake(10, b.size.height - h - 36, 70, 30);
    [toggleBtn setTitle:@"Gizle/Aç" forState:UIControlStateNormal];
    toggleBtn.backgroundColor = [UIColor colorWithWhite:0 alpha:0.8];
    [toggleBtn setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [toggleBtn addTarget:IOKitLogOverlay.class action:@selector(toggleTapped)
        forControlEvents:UIControlEventTouchUpInside];
    [vc.view addSubview:toggleBtn];

    gWindow.hidden = NO;
}

__attribute__((constructor))
static void init_logger(void) {
    rebind_symbols((struct rebinding[1]){
        {"IORegistryEntryCreateCFProperty",
         my_IORegistryEntryCreateCFProperty,
         (void *)&orig_IORegistryEntryCreateCFProperty}
    }, 1);

    // UI hazır olduğunda overlay'i kur (uygulama tam açılmadan scene olmayabilir)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{ setupOverlay(); });
}
