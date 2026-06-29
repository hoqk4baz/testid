//
//  DeviceIdHook.m — Tam versiyon
//  UIDevice + Keychain + Overlay
//  +load ile yüklenir — crash yok
//
//  Build:
//  clang -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//    -miphoneos-version-min=13.0 -shared -fobjc-arc -O2 \
//    -framework UIKit -framework Foundation -framework Security \
//    DeviceIdHook.m fishhook.c -o DeviceIdHook.dylib
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include "fishhook.h"

// ─── Fake değerler ────────────────────────────────────────────────────────
static NSString *const kFakeIdfv     = @"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";
static NSString *const kFakeName     = @"iPhone";
static NSString *const kFakeModel    = @"iPhone15,2";
static NSString *const kFakeSysVer   = @"17.0";
// 52 hex char — lm_new_device_deviceIdentifier için
static NSString *const kFakeDeviceId = @"aabbccddeeff00112233445566778899aabbccddeeff00112233";

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Overlay
// ═══════════════════════════════════════════════════════════════════════════

@interface DHOverlay : UIWindow
+ (instancetype)shared;
- (void)log:(NSString *)msg;
@end

@implementation DHOverlay {
    UITextView *_tv; UIView *_panel; UIButton *_minBtn;
    NSMutableString *_buf; BOOL _min;
}

+ (instancetype)shared {
    static DHOverlay *i; static dispatch_once_t t;
    dispatch_once(&t, ^{
        i = [[DHOverlay alloc] initWithFrame:UIScreen.mainScreen.bounds];
        i.windowLevel = UIWindowLevelAlert + 100;
        i.backgroundColor = UIColor.clearColor;
        i->_buf = [NSMutableString string];
        [i buildUI];
        i.hidden = NO;
    });
    return i;
}

- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *h = [super hitTest:p withEvent:e];
    return h == self ? nil : h;
}

- (void)buildUI {
    CGFloat W = UIScreen.mainScreen.bounds.size.width;
    _panel = [[UIView alloc] initWithFrame:CGRectMake(8, 60, W-16, 260)];
    _panel.backgroundColor = [UIColor colorWithRed:0.04 green:0.04 blue:0.07 alpha:0.95];
    _panel.layer.cornerRadius = 12;
    _panel.clipsToBounds = YES;

    // Başlık
    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0, 0, W-16, 36)];
    bar.backgroundColor = [UIColor colorWithRed:0.08 green:0.08 blue:0.12 alpha:1];
    UILabel *ttl = [[UILabel alloc] initWithFrame:CGRectMake(10, 10, W-110, 16)];
    ttl.text = @"🔧 Device Spoof";
    ttl.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    ttl.textColor = [UIColor colorWithWhite:0.9 alpha:1];
    [bar addSubview:ttl];
    _minBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    _minBtn.frame = CGRectMake(W-16-40, 6, 36, 24);
    [_minBtn setTitle:@"−" forState:UIControlStateNormal];
    _minBtn.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightMedium];
    [_minBtn setTitleColor:[UIColor colorWithWhite:0.6 alpha:1] forState:UIControlStateNormal];
    [_minBtn addTarget:self action:@selector(toggleMin) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:_minBtn];
    [_panel addSubview:bar];

    // Log alanı
    _tv = [[UITextView alloc] initWithFrame:CGRectMake(0, 36, W-16, 260-36-36)];
    _tv.backgroundColor = UIColor.clearColor;
    _tv.editable = NO;
    _tv.selectable = NO;
    _tv.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    _tv.textColor = [UIColor colorWithRed:0.85 green:0.85 blue:0.85 alpha:1];
    [_panel addSubview:_tv];

    // Alt bar
    UIView *bot = [[UIView alloc] initWithFrame:CGRectMake(0, 260-36, W-16, 36)];
    bot.backgroundColor = [UIColor colorWithRed:0.06 green:0.06 blue:0.10 alpha:1];
    UIView *sep = [[UIView alloc] initWithFrame:CGRectMake(0, 0, W-16, 0.5)];
    sep.backgroundColor = [UIColor colorWithWhite:0.2 alpha:1];
    [bot addSubview:sep];

    UIButton *clr = [UIButton buttonWithType:UIButtonTypeCustom];
    clr.frame = CGRectMake(10, 6, 60, 24);
    [clr setTitle:@"Temizle" forState:UIControlStateNormal];
    clr.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
    [clr setTitleColor:[UIColor colorWithWhite:0.5 alpha:1] forState:UIControlStateNormal];
    [clr addTarget:self action:@selector(clearLogs) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:clr];

    UIButton *cpy = [UIButton buttonWithType:UIButtonTypeCustom];
    cpy.frame = CGRectMake(W-16-80, 4, 72, 28);
    [cpy setTitle:@"📋 Kopyala" forState:UIControlStateNormal];
    cpy.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    [cpy setTitleColor:[UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:1] forState:UIControlStateNormal];
    cpy.layer.borderWidth = 0.5;
    cpy.layer.cornerRadius = 6;
    cpy.layer.borderColor = [UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:0.4].CGColor;
    [cpy addTarget:self action:@selector(copyToClipboard) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:cpy];
    [_panel addSubview:bot];

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    [bar addGestureRecognizer:pan];
    [self addSubview:_panel];
}

- (void)log:(NSString *)msg {
    NSAssert([NSThread isMainThread], @"log: must be main thread");
    NSDateFormatter *f = [NSDateFormatter new];
    f.dateFormat = @"HH:mm:ss";
    [_buf appendFormat:@"[%@] %@\n", [f stringFromDate:[NSDate date]], msg];
    _tv.text = _buf;
    [_tv scrollRangeToVisible:NSMakeRange(_buf.length, 0)];
}

- (void)clearLogs { [_buf setString:@""]; _tv.text = @""; }
- (void)copyToClipboard { [UIPasteboard generalPasteboard].string = _buf; }

- (void)toggleMin {
    _min = !_min;
    CGRect f = _panel.frame;
    f.size.height = _min ? 36 : 260;
    [UIView animateWithDuration:0.2 animations:^{ self->_panel.frame = f; }];
    [_minBtn setTitle:_min ? @"+" : @"−" forState:UIControlStateNormal];
}

- (void)handlePan:(UIPanGestureRecognizer *)gr {
    CGPoint t = [gr translationInView:self];
    CGRect f = _panel.frame, s = UIScreen.mainScreen.bounds;
    f.origin.x = MAX(0, MIN(f.origin.x + t.x, s.size.width - f.size.width));
    f.origin.y = MAX(20, MIN(f.origin.y + t.y, s.size.height - f.size.height - 20));
    _panel.frame = f;
    [gr setTranslation:CGPointZero inView:self];
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return 0; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip { return nil; }

@end

// ─── Overlay'e güvenli log ────────────────────────────────────────────────
static void dlog(NSString *msg) {
    NSLog(@"[DHook] %@", msg);
    dispatch_async(dispatch_get_main_queue(), ^{
        [[DHOverlay shared] log:msg];
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - UIDevice hooks
// ═══════════════════════════════════════════════════════════════════════════

static IMP orig_idfv, orig_name, orig_model, orig_sysver;

static NSUUID *h_idfv(id self, SEL _cmd) {
    return [[NSUUID alloc] initWithUUIDString:kFakeIdfv];
}
static NSString *h_name(id self, SEL _cmd) { return kFakeName; }
static NSString *h_model(id self, SEL _cmd) { return kFakeModel; }
static NSString *h_sysver(id self, SEL _cmd) { return kFakeSysVer; }

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Keychain hook (fishhook ile)
// ═══════════════════════════════════════════════════════════════════════════

typedef OSStatus (*SecCopyFn)(CFDictionaryRef, CFTypeRef *);
static SecCopyFn orig_SecItemCopyMatching;

static NSData *hexToData(NSString *hex) {
    NSMutableData *d = [NSMutableData dataWithCapacity:hex.length / 2];
    for (NSUInteger i = 0; i + 1 < hex.length; i += 2) {
        unsigned int byte = 0;
        [[NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(i, 2)]] scanHexInt:&byte];
        uint8_t b = (uint8_t)byte;
        [d appendBytes:&b length:1];
    }
    return d;
}

static OSStatus h_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *res) {
    OSStatus st = orig_SecItemCopyMatching(q, res);
    if (st != errSecSuccess || !res || !*res) return st;

    NSString *acc = (__bridge NSString *)CFDictionaryGetValue(q, kSecAttrAccount);
    if (![acc isEqualToString:@"lm_new_device_deviceIdentifier"]) return st;

    NSData *fakeData = hexToData(kFakeDeviceId);
    CFTypeID tid = CFGetTypeID(*res);

    if (tid == CFDataGetTypeID()) {
        CFRelease(*res);
        *res = (__bridge_retained CFTypeRef)fakeData;
        dlog(@"SPOOF Keychain lm_new_device_deviceIdentifier ✅");
    } else if (tid == CFDictionaryGetTypeID()) {
        NSMutableDictionary *dict = [(__bridge NSDictionary *)*res mutableCopy];
        dict[(id)kSecValueData] = fakeData;
        CFRelease(*res);
        *res = (__bridge_retained CFTypeRef)[dict copy];
        dlog(@"SPOOF Keychain (dict) ✅");
    }
    return st;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hook installer (+load — crash-safe)
// ═══════════════════════════════════════════════════════════════════════════

@interface DHInstaller : NSObject
@end

@implementation DHInstaller

+ (void)load {
    // UIDevice
    Class dev = [UIDevice class];
    [DHInstaller swiz:dev sel:@selector(identifierForVendor) orig:&orig_idfv  new:(IMP)h_idfv];
    [DHInstaller swiz:dev sel:@selector(name)                orig:&orig_name  new:(IMP)h_name];
    [DHInstaller swiz:dev sel:@selector(model)               orig:&orig_model new:(IMP)h_model];
    [DHInstaller swiz:dev sel:@selector(systemVersion)       orig:&orig_sysver new:(IMP)h_sysver];

    // Keychain — fishhook (C fonksiyonu, swizzle çalışmaz)
    struct rebinding b[] = {
        {"SecItemCopyMatching", h_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching}
    };
    rebind_symbols(b, 1);

    NSLog(@"[DHook] +load: tüm hook'lar kuruldu");

    // Overlay — UI hazır olunca
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [[DHOverlay shared] log:@"✅ Device Spoof aktif"];
        [[DHOverlay shared] log:[NSString stringWithFormat:@"IDFV  → %@", kFakeIdfv]];
        [[DHOverlay shared] log:[NSString stringWithFormat:@"Model → %@", kFakeModel]];
        [[DHOverlay shared] log:[NSString stringWithFormat:@"SysVer→ %@", kFakeSysVer]];
        [[DHOverlay shared] log:[NSString stringWithFormat:@"KeyID → %.16s…", kFakeDeviceId.UTF8String]];
    });
}

+ (void)swiz:(Class)cls sel:(SEL)sel orig:(IMP *)orig new:(IMP)newIMP {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    *orig = method_getImplementation(m);
    method_setImplementation(m, newIMP);
}

@end
