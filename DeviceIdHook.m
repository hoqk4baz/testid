//
//  DeviceIdHook.m
//  Flutter uygulaması için güvenli dylib — recursive lock yok, geç init
//
//  Build:
//  clang -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//    -miphoneos-version-min=13.0 -shared -fobjc-arc -O2 \
//    -framework UIKit -framework Foundation -framework Security \
//    -framework CoreFoundation \
//    DeviceIdHook.m fishhook.c -o DeviceIdHook.dylib
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#include "fishhook.h"

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Thread-safe log queue — recursive lock'u önler
// ═══════════════════════════════════════════════════════════════════════════

static dispatch_queue_t logQueue(void) {
    static dispatch_queue_t q;
    static dispatch_once_t t;
    dispatch_once(&t, ^{ q = dispatch_queue_create("dhook.log", DISPATCH_QUEUE_SERIAL); });
    return q;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Log Entry
// ═══════════════════════════════════════════════════════════════════════════

@interface LogEntry : NSObject
@property (nonatomic, copy) NSString *ts, *level, *source, *message;
@end
@implementation LogEntry
- (instancetype)initLevel:(NSString *)lv source:(NSString *)src msg:(NSString *)msg {
    self = [super init];
    NSDateFormatter *f = [NSDateFormatter new];
    f.dateFormat = @"HH:mm:ss.SSS";
    self.ts = [f stringFromDate:[NSDate date]];
    self.level = lv; self.source = src; self.message = msg;
    return self;
}
@end

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Log Cell
// ═══════════════════════════════════════════════════════════════════════════

@interface LogCell : UITableViewCell
- (void)configure:(LogEntry *)e;
@end
@implementation LogCell {
    UILabel *_ts, *_lvl, *_msg;
}
- (instancetype)initWithStyle:(UITableViewCellStyle)s reuseIdentifier:(NSString *)r {
    self = [super initWithStyle:s reuseIdentifier:r];
    self.backgroundColor = UIColor.clearColor;
    self.selectionStyle  = UITableViewCellSelectionStyleNone;

    _ts  = [UILabel new]; _ts.font  = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    _ts.textColor = [UIColor colorWithWhite:0.4 alpha:1]; _ts.translatesAutoresizingMaskIntoConstraints = NO;

    _lvl = [UILabel new]; _lvl.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightBold];
    _lvl.textAlignment = NSTextAlignmentCenter; _lvl.layer.cornerRadius = 3;
    _lvl.layer.masksToBounds = YES; _lvl.translatesAutoresizingMaskIntoConstraints = NO;

    _msg = [UILabel new]; _msg.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    _msg.textColor = [UIColor colorWithRed:0.88 green:0.88 blue:0.88 alpha:1];
    _msg.numberOfLines = 0; _msg.translatesAutoresizingMaskIntoConstraints = NO;

    [self.contentView addSubview:_ts];
    [self.contentView addSubview:_lvl];
    [self.contentView addSubview:_msg];
    [NSLayoutConstraint activateConstraints:@[
        [_ts.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:4],
        [_ts.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:8],
        [_lvl.centerYAnchor constraintEqualToAnchor:_ts.centerYAnchor],
        [_lvl.leadingAnchor constraintEqualToAnchor:_ts.trailingAnchor constant:5],
        [_lvl.widthAnchor constraintEqualToConstant:48], [_lvl.heightAnchor constraintEqualToConstant:14],
        [_msg.topAnchor constraintEqualToAnchor:_ts.bottomAnchor constant:2],
        [_msg.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:8],
        [_msg.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-8],
        [_msg.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-4],
    ]];
    return self;
}
- (void)configure:(LogEntry *)e {
    _ts.text  = e.ts;
    _msg.text = [NSString stringWithFormat:@"[%@] %@", e.source, e.message];
    NSDictionary *p = @{
        @"HOOK":  @[[UIColor colorWithRed:0.47 green:0.75 blue:1.0  alpha:1], [UIColor colorWithRed:0.08 green:0.18 blue:0.32 alpha:1]],
        @"FOUND": @[[UIColor colorWithRed:0.49 green:0.91 blue:0.53 alpha:1], [UIColor colorWithRed:0.08 green:0.23 blue:0.10 alpha:1]],
        @"STACK": @[[UIColor colorWithRed:1.00 green:0.65 blue:0.40 alpha:1], [UIColor colorWithRed:0.28 green:0.14 blue:0.04 alpha:1]],
        @"SCAN":  @[[UIColor colorWithRed:0.40 green:0.85 blue:0.85 alpha:1], [UIColor colorWithRed:0.05 green:0.22 blue:0.22 alpha:1]],
        @"WARN":  @[[UIColor colorWithRed:0.89 green:0.70 blue:0.25 alpha:1], [UIColor colorWithRed:0.28 green:0.18 blue:0.05 alpha:1]],
        @"INFO":  @[[UIColor colorWithWhite:0.55 alpha:1], [UIColor colorWithWhite:0.14 alpha:1]],
    };
    NSArray *pair = p[e.level] ?: p[@"INFO"];
    _lvl.text = e.level; _lvl.textColor = pair[0]; _lvl.backgroundColor = pair[1];
}
@end

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Overlay Window
// ═══════════════════════════════════════════════════════════════════════════

@interface OverlayWindow : UIWindow <UITableViewDataSource, UITableViewDelegate>
+ (instancetype)shared;
- (void)appendLevel:(NSString *)lv source:(NSString *)src message:(NSString *)msg;
@end

@implementation OverlayWindow {
    UIView        *_panel;
    UILabel       *_stats;
    UITableView   *_table;
    UIButton      *_minBtn;
    NSMutableArray<LogEntry *> *_entries;
    NSMutableDictionary       *_counts;
    NSString      *_latestId;
    BOOL           _minimized;
}

+ (instancetype)shared {
    static OverlayWindow *inst;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        inst = [[OverlayWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
        inst.windowLevel     = UIWindowLevelAlert + 100;
        inst.backgroundColor = UIColor.clearColor;
        inst->_entries = [NSMutableArray array];
        inst->_counts  = [NSMutableDictionary dictionary];
        [inst buildUI];
        inst.hidden = NO;
    });
    return inst;
}

- (void)buildUI {
    CGFloat W = UIScreen.mainScreen.bounds.size.width;
    _panel = [[UIView alloc] initWithFrame:CGRectMake(8, 60, W-16, 340)];
    _panel.backgroundColor    = [UIColor colorWithRed:0.04 green:0.04 blue:0.07 alpha:0.95];
    _panel.layer.cornerRadius = 14;
    _panel.layer.borderWidth  = 0.5;
    _panel.layer.borderColor  = [UIColor colorWithWhite:0.28 alpha:0.5].CGColor;
    _panel.clipsToBounds      = YES;

    // Başlık
    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0,0,W-16,38)];
    bar.backgroundColor = [UIColor colorWithRed:0.07 green:0.07 blue:0.11 alpha:1];
    UIView *handle = [[UIView alloc] initWithFrame:CGRectMake((W-16)/2-20, 7, 40, 4)];
    handle.backgroundColor = [UIColor colorWithWhite:0.38 alpha:1];
    handle.layer.cornerRadius = 2;
    [bar addSubview:handle];

    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(12,17,W-70,16)];
    title.text = @"📡 deviceId Hook Logger";
    title.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    title.textColor = [UIColor colorWithWhite:0.88 alpha:1];
    [bar addSubview:title];

    _minBtn = [UIButton buttonWithType:UIButtonTypeCustom];
    _minBtn.frame = CGRectMake(W-16-34, 9, 28, 20);
    [_minBtn setTitle:@"−" forState:UIControlStateNormal];
    _minBtn.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightMedium];
    [_minBtn setTitleColor:[UIColor colorWithWhite:0.6 alpha:1] forState:UIControlStateNormal];
    [_minBtn addTarget:self action:@selector(toggleMin) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:_minBtn];
    [_panel addSubview:bar];

    // Stats
    _stats = [[UILabel alloc] initWithFrame:CGRectMake(10,38,W-36,18)];
    _stats.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    _stats.textColor = [UIColor colorWithWhite:0.42 alpha:1];
    _stats.text = @"Yükleniyor…";
    [_panel addSubview:_stats];

    UIView *sep = [[UIView alloc] initWithFrame:CGRectMake(0,57,W-16,0.5)];
    sep.backgroundColor = [UIColor colorWithWhite:0.2 alpha:1];
    [_panel addSubview:sep];

    // Table
    _table = [[UITableView alloc] initWithFrame:CGRectMake(0,58,W-16,340-58-40)];
    _table.backgroundColor = UIColor.clearColor;
    _table.separatorStyle  = UITableViewCellSeparatorStyleNone;
    _table.dataSource = self; _table.delegate = self;
    _table.rowHeight  = UITableViewAutomaticDimension;
    _table.estimatedRowHeight = 48;
    [_table registerClass:[LogCell class] forCellReuseIdentifier:@"C"];
    [_panel addSubview:_table];

    // Bottom bar
    UIView *bot = [[UIView alloc] initWithFrame:CGRectMake(0,300,W-16,40)];
    bot.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.09 alpha:1];
    UIView *sep2 = [[UIView alloc] initWithFrame:CGRectMake(0,0,W-16,0.5)];
    sep2.backgroundColor = [UIColor colorWithWhite:0.18 alpha:1];
    [bot addSubview:sep2];

    // Temizle
    UIButton *clr = [UIButton buttonWithType:UIButtonTypeCustom];
    clr.frame = CGRectMake(10,8,56,24);
    [clr setTitle:@"Temizle" forState:UIControlStateNormal];
    clr.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
    [clr setTitleColor:[UIColor colorWithWhite:0.42 alpha:1] forState:UIControlStateNormal];
    [clr addTarget:self action:@selector(clearLogs) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:clr];

    // Tara
    UIButton *scan = [UIButton buttonWithType:UIButtonTypeCustom];
    CGFloat bw = 76; CGFloat mid = (W-16)/2;
    scan.frame = CGRectMake(mid-bw/2, 6, bw, 28);
    [scan setTitle:@"🔍 Tara" forState:UIControlStateNormal];
    scan.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    [scan setTitleColor:[UIColor colorWithRed:0.40 green:0.85 blue:0.85 alpha:1] forState:UIControlStateNormal];
    scan.layer.borderWidth  = 0.5;
    scan.layer.borderColor  = [UIColor colorWithRed:0.40 green:0.85 blue:0.85 alpha:0.4].CGColor;
    scan.layer.cornerRadius = 6;
    [scan addTarget:self action:@selector(runScan) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:scan];

    // Kopyala
    UIButton *cpy = [UIButton buttonWithType:UIButtonTypeCustom];
    cpy.tag = 99; cpy.frame = CGRectMake(W-16-88, 6, 80, 28);
    [cpy setTitle:@"📋 Kopyala" forState:UIControlStateNormal];
    cpy.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    [cpy setTitleColor:[UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:1] forState:UIControlStateNormal];
    cpy.layer.borderWidth  = 0.5;
    cpy.layer.borderColor  = [UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:0.4].CGColor;
    cpy.layer.cornerRadius = 6;
    [cpy addTarget:self action:@selector(copyLogs) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:cpy];
    [_panel addSubview:bot];

    // Pan gesture
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    [bar addGestureRecognizer:pan];
    [self addSubview:_panel];
}

// UI thread'den çağrılır — logQueue'dan dispatch_async(main) ile gelir
- (void)appendLevel:(NSString *)lv source:(NSString *)src message:(NSString *)msg {
    NSAssert([NSThread isMainThread], @"appendLevel must be called on main thread");
    LogEntry *e = [[LogEntry alloc] initLevel:lv source:src msg:msg];
    [_entries addObject:e];
    if (src) _counts[src] = @([_counts[src] integerValue] + 1);
    if ([lv isEqualToString:@"FOUND"]) {
        NSRange r = [msg rangeOfString:@"→ "];
        if (r.location != NSNotFound)
            _latestId = [[[msg substringFromIndex:r.location+2] componentsSeparatedByString:@"\n"] firstObject];
    }
    [self updateStats];
    [_table reloadData];
    if (_entries.count > 0)
        [_table scrollToRowAtIndexPath:[NSIndexPath indexPathForRow:_entries.count-1 inSection:0]
                      atScrollPosition:UITableViewScrollPositionBottom animated:NO];
}

- (void)updateStats {
    NSMutableArray *p = [NSMutableArray array];
    [_counts enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *s){ [p addObject:[NSString stringWithFormat:@"%@:%@",k,v]]; }];
    if (_latestId.length > 0) [p addObject:[NSString stringWithFormat:@"id=%.14s…", _latestId.UTF8String]];
    _stats.text = p.count > 0 ? [p componentsJoinedByString:@"  ·  "] : @"Bekleniyor…";
}

- (void)clearLogs {
    [_entries removeAllObjects]; [_counts removeAllObjects]; _latestId = nil;
    _stats.text = @"Temizlendi"; [_table reloadData];
}

- (void)runScan {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0), ^{ [self scanClasses]; });
}

- (void)scanClasses {
    NSArray *keywords = @[@"device",@"identifier",@"fingerprint",@"hwid",@"uniqueid",@"udid",@"serial"];
    unsigned int n = 0;
    Class *cls = objc_copyClassList(&n);
    NSUInteger found = 0;
    for (unsigned int i = 0; i < n; i++) {
        if ([NSBundle bundleForClass:cls[i]] != [NSBundle mainBundle]) continue;
        const char *cn = class_getName(cls[i]);
        for (int cm = 0; cm < 2; cm++) {
            unsigned int mc = 0;
            Method *methods = cm == 0 ? class_copyMethodList(cls[i], &mc)
                                      : class_copyMethodList(object_getClass(cls[i]), &mc);
            for (unsigned int j = 0; j < mc; j++) {
                NSString *sel = NSStringFromSelector(method_getName(methods[j]));
                for (NSString *kw in keywords) {
                    if ([sel.lowercaseString containsString:kw]) {
                        NSString *fmt = [NSString stringWithFormat:@"%@[%s %@]", cm?@"+":@"-", cn, sel];
                        dispatch_async(dispatch_get_main_queue(), ^{
                            [[OverlayWindow shared] appendLevel:@"SCAN" source:@"ClassScan" message:fmt];
                        });
                        found++; break;
                    }
                }
            }
            free(methods);
        }
    }
    free(cls);
    NSString *done = [NSString stringWithFormat:@"Tamamlandı — %lu aday", (unsigned long)found];
    dispatch_async(dispatch_get_main_queue(), ^{
        [[OverlayWindow shared] appendLevel:@"SCAN" source:@"ClassScan" message:done];
    });
}

- (void)copyLogs {
    NSMutableString *t = [NSMutableString string];
    for (LogEntry *e in _entries)
        [t appendFormat:@"[%@][%@][%@] %@\n", e.ts, e.level, e.source, e.message];
    if (_latestId) [t appendFormat:@"\n=== deviceId ===\n%@\n", _latestId];
    [UIPasteboard generalPasteboard].string = t;
    UIButton *b = (UIButton *)[_panel viewWithTag:99];
    NSString *orig = [b titleForState:UIControlStateNormal];
    [b setTitle:@"✅ Kopyalandı" forState:UIControlStateNormal];
    [b setTitleColor:[UIColor colorWithRed:0.49 green:0.91 blue:0.53 alpha:1] forState:UIControlStateNormal];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [b setTitle:orig forState:UIControlStateNormal];
        [b setTitleColor:[UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:1] forState:UIControlStateNormal];
    });
}

- (void)toggleMin {
    _minimized = !_minimized;
    CGRect f = _panel.frame; f.size.height = _minimized ? 38 : 340;
    [UIView animateWithDuration:0.2 animations:^{ self->_panel.frame = f; }];
    [_minBtn setTitle:_minimized ? @"+" : @"−" forState:UIControlStateNormal];
}

- (void)handlePan:(UIPanGestureRecognizer *)pan {
    CGPoint t = [pan translationInView:self];
    CGRect f = _panel.frame, s = UIScreen.mainScreen.bounds;
    f.origin.x = MAX(0, MIN(f.origin.x+t.x, s.size.width-f.size.width));
    f.origin.y = MAX(20, MIN(f.origin.y+t.y, s.size.height-f.size.height-20));
    _panel.frame = f;
    [pan setTranslation:CGPointZero inView:self];
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return _entries.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    LogCell *c = [tv dequeueReusableCellWithIdentifier:@"C" forIndexPath:ip];
    [c configure:_entries[ip.row]]; return c;
}
@end

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Global hookLog — asla main thread'i bloklama
// ═══════════════════════════════════════════════════════════════════════════

static void hookLog(NSString *lv, NSString *src, NSString *fmt, ...) NS_FORMAT_FUNCTION(3,4);
static void hookLog(NSString *lv, NSString *src, NSString *fmt, ...) {
    va_list a; va_start(a, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:a];
    va_end(a);
    NSLog(@"[DHook][%@][%@] %@", lv, src, msg);
    // logQueue → main, iç içe dispatch yok
    dispatch_async(logQueue(), ^{
        dispatch_async(dispatch_get_main_queue(), ^{
            [[OverlayWindow shared] appendLevel:lv source:src message:msg];
        });
    });
}

// App frame'lerini al — swizzle içinden güvenle çağrılabilir
static NSString *callStack(void) {
    NSString *exe = [NSBundle mainBundle].executablePath.lastPathComponent;
    NSMutableArray *f = [NSMutableArray array];
    for (NSString *fr in [NSThread callStackSymbols]) {
        if ([fr containsString:exe] && f.count < 5) [f addObject:fr];
    }
    return f.count > 0 ? [f componentsJoinedByString:@"\n    "]
                       : @"(obfuscated veya C layer)";
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hooks
// ═══════════════════════════════════════════════════════════════════════════

// NSUserDefaults
static IMP orig_objectForKey, orig_stringForKey;

static id h_objectForKey(id self, SEL _cmd, NSString *key) {
    id val = ((id(*)(id,SEL,NSString*))orig_objectForKey)(self,_cmd,key);
    if (val && ([key.lowercaseString containsString:@"device"] ||
                [key.lowercaseString containsString:@"identifier"] ||
                [key.lowercaseString containsString:@"udid"])) {
        hookLog(@"FOUND", @"NSUserDefaults", @"objectForKey:\"%@\" → %@\n    %@", key, val, callStack());
    }
    return val;
}

static id h_stringForKey(id self, SEL _cmd, NSString *key) {
    id val = ((id(*)(id,SEL,NSString*))orig_stringForKey)(self,_cmd,key);
    if (val && ([key.lowercaseString containsString:@"device"] ||
                [key.lowercaseString containsString:@"identifier"])) {
        hookLog(@"FOUND", @"NSUserDefaults", @"stringForKey:\"%@\" → %@\n    %@", key, val, callStack());
    }
    return val;
}

// UIDevice IDFV
static IMP orig_idfv;
static NSUUID *h_idfv(id self, SEL _cmd) {
    NSUUID *u = ((NSUUID*(*)(id,SEL))orig_idfv)(self,_cmd);
    hookLog(@"FOUND", @"IDFV", @"identifierForVendor → %@\n    %@", u.UUIDString, callStack());
    return u;
}

// Keychain
typedef OSStatus (*SecCopyFn)(CFDictionaryRef, CFTypeRef *);
static SecCopyFn orig_SecItemCopyMatching;
static OSStatus h_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *res) {
    OSStatus st = orig_SecItemCopyMatching(q, res);
    if (st == errSecSuccess && res && *res) {
        NSString *acc = (__bridge NSString *)CFDictionaryGetValue(q, kSecAttrAccount);
        NSString *svc = (__bridge NSString *)CFDictionaryGetValue(q, kSecAttrService);
        NSString *val = nil;
        CFTypeID tid = CFGetTypeID(*res);
        if (tid == CFDataGetTypeID())
            val = [[NSString alloc] initWithData:(__bridge NSData *)*res encoding:NSUTF8StringEncoding];
        else if (tid == CFStringGetTypeID())
            val = (__bridge NSString *)*res;
        else if (tid == CFDictionaryGetTypeID()) {
            NSData *d = ((__bridge NSDictionary *)*res)[(id)kSecValueData];
            if (d) val = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        }
        NSString *label = acc ?: svc ?: @"?";
        BOOL interesting = [label.lowercaseString containsString:@"device"] ||
                           [label.lowercaseString containsString:@"id"]     ||
                           (val.length >= 32);
        hookLog(interesting ? @"FOUND" : @"INFO", @"Keychain",
                @"account=\"%@\" svc=\"%@\" val=%@\n    %@",
                acc?:@"-", svc?:@"-", val?:@"<binary>", callStack());
    }
    return st;
}

// CFPreferences
typedef CFPropertyListRef (*CFPrefFn)(CFStringRef,CFStringRef,CFStringRef,CFStringRef);
static CFPrefFn orig_CFPreferencesCopyValue;
static CFPropertyListRef h_CFPreferencesCopyValue(CFStringRef k,CFStringRef app,CFStringRef u,CFStringRef h) {
    CFPropertyListRef val = orig_CFPreferencesCopyValue(k,app,u,h);
    NSString *key = (__bridge NSString *)k;
    if ([key.lowercaseString containsString:@"device"] || [key.lowercaseString containsString:@"identifier"]) {
        hookLog(@"FOUND", @"CFPreferences", @"key=\"%@\" → %@\n    %@", key, (__bridge id)val, callStack());
    }
    return val;
}

// ─── Swizzle helper ───────────────────────────────────────────────────────
static void swizzle(Class cls, SEL sel, IMP *orig, IMP newIMP) {
    Method m = class_getInstanceMethod(cls, sel) ?: class_getClassMethod(cls, sel);
    if (!m) { hookLog(@"WARN",@"Swizzle",@"%@ → %@ bulunamadı", NSStringFromClass(cls), NSStringFromSelector(sel)); return; }
    *orig = method_getImplementation(m);
    method_setImplementation(m, newIMP);
    hookLog(@"HOOK",@"Swizzle",@"✓ [%@ %@]", NSStringFromClass(cls), NSStringFromSelector(sel));
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Constructor
// Flutter/Dart tamamen başladıktan sonra hook'la — 2 sn gecikme
// ═══════════════════════════════════════════════════════════════════════════

__attribute__((constructor))
static void init(void) {
    // Overlay'i hemen oluştur ama hook'ları geciktir
    // Flutter engine + Dart VM init tamamlansın
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{

        // Overlay'i göster
        [OverlayWindow shared];
        hookLog(@"INFO", @"dylib", @"DeviceId Hook Logger — hazır (iOS %@)",
                [[UIDevice currentDevice] systemVersion]);
        hookLog(@"INFO", @"dylib", @"Flutter app tespit edildi: com.farah.chat");
        hookLog(@"INFO", @"dylib", @"🔍 Tara → app'in tüm deviceId method'larını listeler");

        // Hook'lar
        swizzle([NSUserDefaults class], @selector(objectForKey:), &orig_objectForKey, (IMP)h_objectForKey);
        swizzle([NSUserDefaults class], @selector(stringForKey:),  &orig_stringForKey,  (IMP)h_stringForKey);
        swizzle([UIDevice class], @selector(identifierForVendor),  &orig_idfv,          (IMP)h_idfv);

        // Keychain fishhook
        struct rebinding kb[] = {{"SecItemCopyMatching", h_SecItemCopyMatching, (void**)&orig_SecItemCopyMatching}};
        rebind_symbols(kb, 1);
        hookLog(@"HOOK", @"Keychain", @"✓ SecItemCopyMatching hooked");

        // CFPreferences fishhook
        struct rebinding pb[] = {{"CFPreferencesCopyValue", h_CFPreferencesCopyValue, (void**)&orig_CFPreferencesCopyValue}};
        rebind_symbols(pb, 1);
        hookLog(@"HOOK", @"CFPreferences", @"✓ CFPreferencesCopyValue hooked");

        hookLog(@"INFO", @"dylib", @"Tüm hook'lar aktif — uygulama ile etkileşime gir");
    });
}
