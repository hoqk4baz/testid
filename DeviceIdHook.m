//
//  DeviceIdHook.m
//  Tek dosya — overlay UI + tüm hook'lar + call stack + class scanner
//
//  Build (GitHub Actions veya lokal):
//  clang -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//    -miphoneos-version-min=13.0 -shared -fmodules -fobjc-arc -O2 \
//    -framework UIKit -framework Foundation -framework Security \
//    -framework CoreFoundation \
//    DeviceIdHook.m fishhook.c -o DeviceIdHook.dylib
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#include "fishhook.h"

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Log entry
// ═══════════════════════════════════════════════════════════════════════════

@interface LogEntry : NSObject
@property (nonatomic, copy) NSString *timestamp;
@property (nonatomic, copy) NSString *level;
@property (nonatomic, copy) NSString *source;
@property (nonatomic, copy) NSString *message;
@end

@implementation LogEntry
- (instancetype)initWithLevel:(NSString *)level source:(NSString *)source message:(NSString *)msg {
    self = [super init];
    NSDateFormatter *f = [[NSDateFormatter alloc] init];
    f.dateFormat = @"HH:mm:ss.SSS";
    self.timestamp = [f stringFromDate:[NSDate date]];
    self.level   = level;
    self.source  = source;
    self.message = msg;
    return self;
}
@end

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Log cell
// ═══════════════════════════════════════════════════════════════════════════

@interface LogCell : UITableViewCell
@property (nonatomic, strong) UILabel *tsLabel;
@property (nonatomic, strong) UILabel *lvlLabel;
@property (nonatomic, strong) UILabel *msgLabel;
@end

@implementation LogCell
- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)id {
    self = [super initWithStyle:style reuseIdentifier:id];
    self.backgroundColor    = [UIColor clearColor];
    self.selectionStyle     = UITableViewCellSelectionStyleNone;

    _tsLabel = [[UILabel alloc] init];
    _tsLabel.font      = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    _tsLabel.textColor = [UIColor colorWithWhite:0.45 alpha:1];
    _tsLabel.translatesAutoresizingMaskIntoConstraints = NO;

    _lvlLabel = [[UILabel alloc] init];
    _lvlLabel.font            = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightBold];
    _lvlLabel.textAlignment   = NSTextAlignmentCenter;
    _lvlLabel.layer.cornerRadius   = 3;
    _lvlLabel.layer.masksToBounds  = YES;
    _lvlLabel.translatesAutoresizingMaskIntoConstraints = NO;

    _msgLabel = [[UILabel alloc] init];
    _msgLabel.font          = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    _msgLabel.textColor     = [UIColor colorWithRed:0.9 green:0.9 blue:0.9 alpha:1];
    _msgLabel.numberOfLines = 0;
    _msgLabel.translatesAutoresizingMaskIntoConstraints = NO;

    [self.contentView addSubview:_tsLabel];
    [self.contentView addSubview:_lvlLabel];
    [self.contentView addSubview:_msgLabel];

    [NSLayoutConstraint activateConstraints:@[
        [_tsLabel.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:4],
        [_tsLabel.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:8],

        [_lvlLabel.centerYAnchor constraintEqualToAnchor:_tsLabel.centerYAnchor],
        [_lvlLabel.leadingAnchor constraintEqualToAnchor:_tsLabel.trailingAnchor constant:5],
        [_lvlLabel.widthAnchor constraintEqualToConstant:46],
        [_lvlLabel.heightAnchor constraintEqualToConstant:14],

        [_msgLabel.topAnchor constraintEqualToAnchor:_tsLabel.bottomAnchor constant:2],
        [_msgLabel.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:8],
        [_msgLabel.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-8],
        [_msgLabel.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-4],
    ]];
    return self;
}

- (void)configureWithEntry:(LogEntry *)e {
    _tsLabel.text  = e.timestamp;
    _msgLabel.text = [NSString stringWithFormat:@"[%@] %@", e.source, e.message];

    NSDictionary *palette = @{
        @"HOOK":  @[[UIColor colorWithRed:0.47 green:0.75 blue:1.00 alpha:1], [UIColor colorWithRed:0.08 green:0.18 blue:0.32 alpha:1]],
        @"FOUND": @[[UIColor colorWithRed:0.49 green:0.91 blue:0.53 alpha:1], [UIColor colorWithRed:0.08 green:0.23 blue:0.10 alpha:1]],
        @"SPOOF": @[[UIColor colorWithRed:0.82 green:0.66 blue:1.00 alpha:1], [UIColor colorWithRed:0.18 green:0.10 blue:0.28 alpha:1]],
        @"STACK": @[[UIColor colorWithRed:1.00 green:0.65 blue:0.40 alpha:1], [UIColor colorWithRed:0.30 green:0.16 blue:0.05 alpha:1]],
        @"SCAN":  @[[UIColor colorWithRed:0.40 green:0.85 blue:0.85 alpha:1], [UIColor colorWithRed:0.05 green:0.22 blue:0.22 alpha:1]],
        @"WARN":  @[[UIColor colorWithRed:0.89 green:0.70 blue:0.25 alpha:1], [UIColor colorWithRed:0.28 green:0.18 blue:0.05 alpha:1]],
        @"INFO":  @[[UIColor colorWithWhite:0.55 alpha:1],                     [UIColor colorWithWhite:0.14 alpha:1]],
    };
    NSArray *pair = palette[e.level] ?: palette[@"INFO"];
    _lvlLabel.text            = e.level;
    _lvlLabel.textColor       = pair[0];
    _lvlLabel.backgroundColor = pair[1];
}
@end

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Overlay window (forward declare for hookLog)
// ═══════════════════════════════════════════════════════════════════════════

@interface OverlayWindow : UIWindow <UITableViewDataSource, UITableViewDelegate>
+ (instancetype)shared;
- (void)logLevel:(NSString *)level source:(NSString *)src message:(NSString *)msg;
@end

// ─── Global log helper ────────────────────────────────────────────────────
static void hookLog(NSString *level, NSString *src, NSString *fmt, ...) NS_FORMAT_FUNCTION(3,4);
static void hookLog(NSString *level, NSString *src, NSString *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    NSLog(@"[DHook][%@][%@] %@", level, src, msg);
    dispatch_async(dispatch_get_main_queue(), ^{
        [[OverlayWindow shared] logLevel:level source:src message:msg];
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hook declarations (forward)
// ═══════════════════════════════════════════════════════════════════════════

// NSUserDefaults
static IMP orig_objectForKey;
static IMP orig_stringForKey;

// UIDevice
static IMP orig_identifierForVendor;

// NSURLRequest
static IMP orig_allHTTPHeaderFields;
static IMP orig_valueForHTTPHeaderField;

// Keychain
typedef OSStatus (*SecCopyFn)(CFDictionaryRef, CFTypeRef *);
static SecCopyFn orig_SecItemCopyMatching;

// CFPreferences
typedef CFPropertyListRef (*CFPrefsFn)(CFStringRef, CFStringRef, CFStringRef, CFStringRef);
static CFPrefsFn orig_CFPreferencesCopyValue;

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Helpers
// ═══════════════════════════════════════════════════════════════════════════

static BOOL looksLikeDeviceId(NSString *key, id value) {
    if (!key) return NO;
    NSString *kl = key.lowercaseString;
    if ([kl containsString:@"device"]      ||
        [kl containsString:@"deviceid"]    ||
        [kl containsString:@"identifier"]  ||
        [kl containsString:@"udid"]        ||
        [kl containsString:@"uuid"]        ||
        [kl containsString:@"fingerprint"] ||
        [kl containsString:@"hwid"]        ||
        [kl containsString:@"uniqueid"]    ||
        [kl containsString:@"machine"])    return YES;

    // 52 karakter hex string mi?
    if ([value isKindOfClass:[NSString class]]) {
        NSString *v = (NSString *)value;
        if (v.length >= 32) {
            NSCharacterSet *nonHex = [[NSCharacterSet characterSetWithCharactersInString:
                                       @"0123456789abcdefABCDEF-"] invertedSet];
            if ([v rangeOfCharacterFromSet:nonHex].location == NSNotFound) return YES;
        }
    }
    return NO;
}

// Call stack'in sadece app'e ait frame'lerini döndür
static NSString *appCallStack(void) {
    NSArray *all   = [NSThread callStackSymbols];
    NSString *appName = [NSBundle mainBundle].executablePath.lastPathComponent;
    NSMutableArray *frames = [NSMutableArray array];
    NSUInteger count = 0;
    for (NSString *frame in all) {
        if ([frame containsString:appName] && count < 6) {
            [frames addObject:frame];
            count++;
        }
    }
    return frames.count > 0
        ? [frames componentsJoinedByString:@"\n    "]
        : @"(uygulama frame bulunamadı — obfuscated olabilir)";
}

// Swizzle helper
static void swizzle(Class cls, SEL sel, IMP *origOut, IMP newIMP) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) m = class_getClassMethod(cls, sel);
    if (!m) { hookLog(@"WARN", @"Swizzle", @"%@ → %@ bulunamadı", NSStringFromClass(cls), NSStringFromSelector(sel)); return; }
    *origOut = method_getImplementation(m);
    method_setImplementation(m, newIMP);
    hookLog(@"HOOK", @"Swizzle", @"✓ [%@ %@]", NSStringFromClass(cls), NSStringFromSelector(sel));
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hook implementations
// ═══════════════════════════════════════════════════════════════════════════

// ── NSUserDefaults ────────────────────────────────────────────────────────
static id swizzled_objectForKey(id self, SEL _cmd, NSString *key) {
    id val = ((id(*)(id,SEL,NSString*))orig_objectForKey)(self, _cmd, key);
    if (looksLikeDeviceId(key, val)) {
        hookLog(@"FOUND", @"NSUserDefaults", @"objectForKey:\"%@\" → %@\n    %@", key, val, appCallStack());
    }
    return val;
}

static id swizzled_stringForKey(id self, SEL _cmd, NSString *key) {
    id val = ((id(*)(id,SEL,NSString*))orig_stringForKey)(self, _cmd, key);
    if (looksLikeDeviceId(key, val)) {
        hookLog(@"FOUND", @"NSUserDefaults", @"stringForKey:\"%@\" → %@\n    %@", key, val, appCallStack());
    }
    return val;
}

// ── UIDevice IDFV ─────────────────────────────────────────────────────────
static NSUUID *swizzled_identifierForVendor(id self, SEL _cmd) {
    NSUUID *uuid = ((NSUUID*(*)(id,SEL))orig_identifierForVendor)(self, _cmd);
    hookLog(@"FOUND", @"IDFV", @"identifierForVendor → %@\n    %@", uuid.UUIDString, appCallStack());
    return uuid;
}

// ── HTTP headers — EN ÖNEMLİ: hangi method set etti? ─────────────────────
static NSDictionary *swizzled_allHTTPHeaderFields(id self, SEL _cmd) {
    NSDictionary *headers = ((NSDictionary*(*)(id,SEL))orig_allHTTPHeaderFields)(self, _cmd);
    [headers enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *val, BOOL *stop) {
        if ([key.lowercaseString containsString:@"device"]     ||
            [key.lowercaseString containsString:@"identifier"] ||
            [key.lowercaseString containsString:@"fingerprint"]) {
            hookLog(@"FOUND", @"HTTP-Header", @"%@: %@", key, val);
            hookLog(@"STACK", @"HTTP-Header", @"deviceId'yi set eden call stack:\n    %@", appCallStack());
        }
    }];
    return headers;
}

static NSString *swizzled_valueForHTTPHeaderField(id self, SEL _cmd, NSString *field) {
    NSString *val = ((NSString*(*)(id,SEL,NSString*))orig_valueForHTTPHeaderField)(self, _cmd, field);
    if ([field.lowercaseString containsString:@"device"]) {
        hookLog(@"FOUND", @"HTTP-Header", @"valueForHTTPHeaderField:\"%@\" → %@", field, val);
    }
    return val;
}

// ── Keychain ──────────────────────────────────────────────────────────────
static OSStatus hook_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus st = orig_SecItemCopyMatching(query, result);
    if (st == errSecSuccess && result && *result) {
        NSString *acc = (__bridge NSString *)CFDictionaryGetValue(query, kSecAttrAccount);
        NSString *svc = (__bridge NSString *)CFDictionaryGetValue(query, kSecAttrService);

        NSString *valStr = nil;
        CFTypeID tid = CFGetTypeID(*result);
        if (tid == CFDataGetTypeID()) {
            valStr = [[NSString alloc] initWithData:(__bridge NSData *)*result encoding:NSUTF8StringEncoding];
        } else if (tid == CFStringGetTypeID()) {
            valStr = (__bridge NSString *)*result;
        } else if (tid == CFDictionaryGetTypeID()) {
            NSData *d = ((__bridge NSDictionary *)*result)[(id)kSecValueData];
            if (d) valStr = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        }

        NSString *label = acc ?: svc ?: @"?";
        if (looksLikeDeviceId(label, valStr)) {
            hookLog(@"FOUND", @"Keychain", @"account=\"%@\" service=\"%@\" → %@\n    %@",
                    acc ?: @"-", svc ?: @"-", valStr ?: @"<binary>", appCallStack());
        } else {
            hookLog(@"INFO", @"Keychain", @"account=\"%@\" service=\"%@\"", acc ?: @"-", svc ?: @"-");
        }
    }
    return st;
}

// ── CFPreferences ─────────────────────────────────────────────────────────
static CFPropertyListRef hook_CFPreferencesCopyValue(CFStringRef key, CFStringRef appID,
                                                      CFStringRef user, CFStringRef host) {
    CFPropertyListRef val = orig_CFPreferencesCopyValue(key, appID, user, host);
    NSString *k = (__bridge NSString *)key;
    NSString *v = (__bridge id)val;
    if (looksLikeDeviceId(k, [v isKindOfClass:[NSString class]] ? v : nil)) {
        hookLog(@"FOUND", @"CFPreferences", @"key=\"%@\" → %@\n    %@", k, v, appCallStack());
    }
    return val;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Class scanner
// Uygulamanın kendi class'larını tarar, "device/identifier/fingerprint"
// geçen tüm method'ları loglar — Android'deki gibi kaynağı bul
// ═══════════════════════════════════════════════════════════════════════════

static void scanAppClasses(void) {
    hookLog(@"SCAN", @"Scanner", @"App class'ları taranıyor…");

    NSString *execPath = [NSBundle mainBundle].executablePath.lastPathComponent;
    NSArray *keywords = @[@"device", @"identifier", @"fingerprint", @"hwid",
                          @"uniqueid", @"udid", @"machine", @"serial"];

    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);
    NSUInteger found = 0;

    for (unsigned int i = 0; i < classCount; i++) {
        Class cls = classes[i];

        // Sadece main bundle'daki class'lar
        NSBundle *b = [NSBundle bundleForClass:cls];
        if (b != [NSBundle mainBundle]) continue;

        const char *className = class_getName(cls);

        // Instance methods
        unsigned int mCount = 0;
        Method *methods = class_copyMethodList(cls, &mCount);
        for (unsigned int j = 0; j < mCount; j++) {
            NSString *sel = NSStringFromSelector(method_getName(methods[j]));
            NSString *sl  = sel.lowercaseString;
            for (NSString *kw in keywords) {
                if ([sl containsString:kw]) {
                    hookLog(@"SCAN", @"ClassScan",
                            @"-[%s %@]  ← deviceId kaynağı olabilir", className, sel);
                    found++;
                    break;
                }
            }
        }
        free(methods);

        // Class methods
        Method *cMethods = class_copyMethodList(object_getClass(cls), &mCount);
        for (unsigned int j = 0; j < mCount; j++) {
            NSString *sel = NSStringFromSelector(method_getName(cMethods[j]));
            NSString *sl  = sel.lowercaseString;
            for (NSString *kw in keywords) {
                if ([sl containsString:kw]) {
                    hookLog(@"SCAN", @"ClassScan",
                            @"+[%s %@]  ← deviceId kaynağı olabilir", className, sel);
                    found++;
                    break;
                }
            }
        }
        free(cMethods);
    }
    free(classes);

    hookLog(@"SCAN", @"Scanner", @"Tamamlandı — %lu aday method bulundu", (unsigned long)found);
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Overlay window implementation
// ═══════════════════════════════════════════════════════════════════════════

@implementation OverlayWindow {
    UIView   *_panel;
    UILabel  *_statsLabel;
    UITableView *_table;
    UIButton *_minBtn;
    NSMutableArray<LogEntry *> *_entries;
    NSMutableDictionary *_srcCounts;
    NSString *_latestVal;
    BOOL     _minimized;
}

+ (instancetype)shared {
    static OverlayWindow *inst;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        UIWindowScene *scene = nil;
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes)
            if ([s isKindOfClass:[UIWindowScene class]]) { scene = (UIWindowScene *)s; break; }
        inst = scene ? [[OverlayWindow alloc] initWithWindowScene:scene]
                     : [[OverlayWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
        inst.windowLevel       = UIWindowLevelAlert + 100;
        inst.backgroundColor   = UIColor.clearColor;
        inst.hidden            = NO;
        inst->_entries   = [NSMutableArray array];
        inst->_srcCounts = [NSMutableDictionary dictionary];
        [inst buildUI];
    });
    return inst;
}

- (void)buildUI {
    CGFloat W = UIScreen.mainScreen.bounds.size.width;
    _panel = [[UIView alloc] initWithFrame:CGRectMake(8, 60, W - 16, 340)];
    _panel.backgroundColor      = [UIColor colorWithRed:0.04 green:0.04 blue:0.07 alpha:0.95];
    _panel.layer.cornerRadius   = 14;
    _panel.layer.borderWidth    = 0.5;
    _panel.layer.borderColor    = [UIColor colorWithWhite:0.3 alpha:0.4].CGColor;
    _panel.clipsToBounds        = YES;

    // Başlık bar
    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0,0,_panel.bounds.size.width,38)];
    bar.backgroundColor = [UIColor colorWithRed:0.07 green:0.07 blue:0.11 alpha:1];
    [_panel addSubview:bar];

    UIView *handle = [[UIView alloc] initWithFrame:CGRectMake(W/2-28,7,40,4)];
    handle.backgroundColor     = [UIColor colorWithWhite:0.4 alpha:1];
    handle.layer.cornerRadius  = 2;
    [bar addSubview:handle];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(12,18,W-70,16)];
    title.text      = @"📡 deviceId Hook Logger";
    title.font      = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    title.textColor = [UIColor colorWithWhite:0.9 alpha:1];
    [bar addSubview:title];

    _minBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    _minBtn.frame = CGRectMake(_panel.bounds.size.width - 34, 9, 26, 20);
    [_minBtn setTitle:@"−" forState:UIControlStateNormal];
    _minBtn.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightMedium];
    [_minBtn setTitleColor:[UIColor colorWithWhite:0.65 alpha:1] forState:UIControlStateNormal];
    [_minBtn addTarget:self action:@selector(toggleMin) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:_minBtn];

    // Stats
    _statsLabel = [[UILabel alloc] initWithFrame:CGRectMake(10,38,_panel.bounds.size.width-20,18)];
    _statsLabel.font      = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    _statsLabel.textColor = [UIColor colorWithWhite:0.45 alpha:1];
    _statsLabel.text      = @"Hook'lar yükleniyor…";
    [_panel addSubview:_statsLabel];

    UIView *sep = [[UIView alloc] initWithFrame:CGRectMake(0,57,_panel.bounds.size.width,0.5)];
    sep.backgroundColor = [UIColor colorWithWhite:0.22 alpha:1];
    [_panel addSubview:sep];

    // Table
    CGFloat th = _panel.bounds.size.height - 57 - 40;
    _table = [[UITableView alloc] initWithFrame:CGRectMake(0,58,_panel.bounds.size.width,th)];
    _table.backgroundColor  = UIColor.clearColor;
    _table.separatorStyle   = UITableViewCellSeparatorStyleNone;
    _table.dataSource       = self;
    _table.delegate         = self;
    _table.rowHeight        = UITableViewAutomaticDimension;
    _table.estimatedRowHeight = 48;
    [_table registerClass:[LogCell class] forCellReuseIdentifier:@"C"];
    [_panel addSubview:_table];

    // Bottom bar
    CGFloat bY = _panel.bounds.size.height - 40;
    UIView *bot = [[UIView alloc] initWithFrame:CGRectMake(0,bY,_panel.bounds.size.width,40)];
    bot.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.09 alpha:1];
    UIView *sep2 = [[UIView alloc] initWithFrame:CGRectMake(0,0,_panel.bounds.size.width,0.5)];
    sep2.backgroundColor = [UIColor colorWithWhite:0.2 alpha:1];
    [bot addSubview:sep2];

    UIButton *clrBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    clrBtn.frame = CGRectMake(10,8,56,24);
    [clrBtn setTitle:@"Temizle" forState:UIControlStateNormal];
    clrBtn.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
    [clrBtn setTitleColor:[UIColor colorWithWhite:0.45 alpha:1] forState:UIControlStateNormal];
    [clrBtn addTarget:self action:@selector(clearLogs) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:clrBtn];

    UIButton *scanBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    CGFloat sw = 80;
    scanBtn.frame = CGRectMake((_panel.bounds.size.width - sw) / 2, 6, sw, 28);
    [scanBtn setTitle:@"🔍 Tara" forState:UIControlStateNormal];
    scanBtn.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    [scanBtn setTitleColor:[UIColor colorWithRed:0.40 green:0.85 blue:0.85 alpha:1] forState:UIControlStateNormal];
    scanBtn.layer.borderWidth = 0.5;
    scanBtn.layer.borderColor = [UIColor colorWithRed:0.40 green:0.85 blue:0.85 alpha:0.4].CGColor;
    scanBtn.layer.cornerRadius = 6;
    [scanBtn addTarget:self action:@selector(runScan) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:scanBtn];

    UIButton *cpyBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    cpyBtn.frame = CGRectMake(_panel.bounds.size.width - 86, 6, 78, 28);
    cpyBtn.tag = 99;
    [cpyBtn setTitle:@"📋 Kopyala" forState:UIControlStateNormal];
    cpyBtn.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    [cpyBtn setTitleColor:[UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:1] forState:UIControlStateNormal];
    cpyBtn.layer.borderWidth  = 0.5;
    cpyBtn.layer.borderColor  = [UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:0.4].CGColor;
    cpyBtn.layer.cornerRadius = 6;
    [cpyBtn addTarget:self action:@selector(copyLogs) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:cpyBtn];

    [_panel addSubview:bot];

    // Pan — sürükle
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    [bar addGestureRecognizer:pan];

    [self addSubview:_panel];
}

- (void)logLevel:(NSString *)level source:(NSString *)src message:(NSString *)msg {
    LogEntry *e = [[LogEntry alloc] initWithLevel:level source:src message:msg];
    [_entries addObject:e];
    if (src && ![src isEqualToString:@"—"]) {
        _srcCounts[src] = @([_srcCounts[src] integerValue] + 1);
    }
    if ([level isEqualToString:@"FOUND"]) {
        // Değeri yakala
        NSRange r = [msg rangeOfString:@"→ "];
        if (r.location != NSNotFound) {
            _latestVal = [[msg substringFromIndex:r.location + 2]
                          componentsSeparatedByString:@"\n"].firstObject;
        }
    }
    [self updateStats];
    [_table reloadData];
    if (_entries.count > 0) {
        [_table scrollToRowAtIndexPath:[NSIndexPath indexPathForRow:_entries.count-1 inSection:0]
                      atScrollPosition:UITableViewScrollPositionBottom animated:NO];
    }
}

- (void)updateStats {
    NSMutableArray *parts = [NSMutableArray array];
    for (NSString *k in _srcCounts) [parts addObject:[NSString stringWithFormat:@"%@:%@", k, _srcCounts[k]]];
    if (_latestVal.length > 0) {
        NSString *preview = _latestVal.length > 14 ? [[_latestVal substringToIndex:14] stringByAppendingString:@"…"] : _latestVal;
        [parts addObject:[NSString stringWithFormat:@"id=%@", preview]];
    }
    _statsLabel.text = parts.count > 0 ? [parts componentsJoinedByString:@"  ·  "] : @"Bekleniyor…";
}

- (void)clearLogs {
    [_entries removeAllObjects];
    [_srcCounts removeAllObjects];
    _latestVal = nil;
    _statsLabel.text = @"Temizlendi…";
    [_table reloadData];
}

- (void)runScan {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        scanAppClasses();
    });
}

- (void)copyLogs {
    NSMutableString *text = [NSMutableString string];
    for (LogEntry *e in _entries) {
        [text appendFormat:@"[%@][%@][%@] %@\n", e.timestamp, e.level, e.source, e.message];
    }
    if (_latestVal) [text appendFormat:@"\n=== Tespit edilen deviceId ===\n%@\n", _latestVal];
    [UIPasteboard generalPasteboard].string = text;

    UIButton *btn = (UIButton *)[_panel viewWithTag:99];
    if (!btn) return;
    NSString *orig = [btn titleForState:UIControlStateNormal];
    [btn setTitle:@"✅ Kopyalandı" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor colorWithRed:0.49 green:0.91 blue:0.53 alpha:1] forState:UIControlStateNormal];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1.5*NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [btn setTitle:orig forState:UIControlStateNormal];
        [btn setTitleColor:[UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:1] forState:UIControlStateNormal];
    });
}

- (void)toggleMin {
    _minimized = !_minimized;
    CGRect f = _panel.frame;
    f.size.height = _minimized ? 38 : 340;
    [UIView animateWithDuration:0.2 animations:^{ self->_panel.frame = f; }];
    [_minBtn setTitle:_minimized ? @"+" : @"−" forState:UIControlStateNormal];
}

- (void)handlePan:(UIPanGestureRecognizer *)pan {
    CGPoint t = [pan translationInView:self];
    CGRect f  = _panel.frame, s = UIScreen.mainScreen.bounds;
    f.origin.x = MAX(0, MIN(f.origin.x + t.x, s.size.width  - f.size.width));
    f.origin.y = MAX(20, MIN(f.origin.y + t.y, s.size.height - f.size.height - 20));
    _panel.frame = f;
    [pan setTranslation:CGPointZero inView:self];
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return _entries.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    LogCell *cell = [tv dequeueReusableCellWithIdentifier:@"C" forIndexPath:ip];
    [cell configureWithEntry:_entries[ip.row]];
    return cell;
}

@end

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Constructor — dylib yüklenince çalışır
// ═══════════════════════════════════════════════════════════════════════════

__attribute__((constructor))
static void init(void) {
    // Overlay'i başlat
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.6*NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [OverlayWindow shared]; // paneli oluştur ve göster
        hookLog(@"INFO", @"dylib", @"DeviceId Hook Logger v2 — hazır");
        hookLog(@"INFO", @"dylib", @"🔍 Tara butonuna bas: app'in deviceId method'larını listeler");
    });

    // 1. NSUserDefaults
    swizzle([NSUserDefaults class], @selector(objectForKey:), &orig_objectForKey, (IMP)swizzled_objectForKey);
    swizzle([NSUserDefaults class], @selector(stringForKey:), &orig_stringForKey, (IMP)swizzled_stringForKey);

    // 2. UIDevice IDFV
    swizzle([UIDevice class], @selector(identifierForVendor), &orig_identifierForVendor, (IMP)swizzled_identifierForVendor);

    // 3. NSURLRequest — HTTP header'ları izle + call stack
    swizzle([NSURLRequest class],        @selector(allHTTPHeaderFields),        &orig_allHTTPHeaderFields,       (IMP)swizzled_allHTTPHeaderFields);
    swizzle([NSMutableURLRequest class], @selector(allHTTPHeaderFields),        &orig_allHTTPHeaderFields,       (IMP)swizzled_allHTTPHeaderFields);
    swizzle([NSURLRequest class],        @selector(valueForHTTPHeaderField:),   &orig_valueForHTTPHeaderField,   (IMP)swizzled_valueForHTTPHeaderField);

    // 4. Keychain (fishhook)
    {
        struct rebinding b[] = {{"SecItemCopyMatching", hook_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching}};
        rebind_symbols(b, 1);
        hookLog(@"HOOK", @"Keychain", @"✓ SecItemCopyMatching hooked");
    }

    // 5. CFPreferences (fishhook)
    {
        struct rebinding b[] = {{"CFPreferencesCopyValue", hook_CFPreferencesCopyValue, (void **)&orig_CFPreferencesCopyValue}};
        rebind_symbols(b, 1);
        hookLog(@"HOOK", @"CFPreferences", @"✓ CFPreferencesCopyValue hooked");
    }
}
