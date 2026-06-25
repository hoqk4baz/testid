//
//  DeviceIdHook.m  — Log + Spoof (tüm kaynaklar)
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
#import <dlfcn.h>
#include "fishhook.h"

// ─── Ayarlar ─────────────────────────────────────────────────────────────
// Hedef 52 char hex → tam bu format
static NSString *const kFakeDeviceId = @"77bc647fc7ccc3aec3cd94eace776e68fc23b1661774527200000000";
static BOOL kSpoofEnabled = YES;

// ─── Log queue ───────────────────────────────────────────────────────────
static dispatch_queue_t logQ(void) {
    static dispatch_queue_t q; static dispatch_once_t t;
    dispatch_once(&t, ^{ q = dispatch_queue_create("dhook.log", DISPATCH_QUEUE_SERIAL); });
    return q;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - UI
// ═══════════════════════════════════════════════════════════════════════════

@interface LogEntry : NSObject
@property (nonatomic, copy) NSString *ts, *level, *source, *message;
@end
@implementation LogEntry
- (instancetype)initLevel:(NSString *)lv source:(NSString *)src msg:(NSString *)msg {
    self = [super init];
    NSDateFormatter *f = [NSDateFormatter new]; f.dateFormat = @"HH:mm:ss.SSS";
    self.ts = [f stringFromDate:[NSDate date]]; self.level = lv; self.source = src; self.message = msg;
    return self;
}
@end

@interface DHLogCell : UITableViewCell
- (void)configure:(LogEntry *)e;
@end
@implementation DHLogCell { UILabel *_ts, *_lvl, *_msg; }
- (instancetype)initWithStyle:(UITableViewCellStyle)s reuseIdentifier:(NSString *)r {
    self = [super initWithStyle:s reuseIdentifier:r];
    self.backgroundColor = UIColor.clearColor; self.selectionStyle = UITableViewCellSelectionStyleNone;
    _ts  = [UILabel new]; _ts.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    _ts.textColor = [UIColor colorWithWhite:0.4 alpha:1]; _ts.translatesAutoresizingMaskIntoConstraints = NO;
    _lvl = [UILabel new]; _lvl.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightBold];
    _lvl.textAlignment = NSTextAlignmentCenter; _lvl.layer.cornerRadius = 3; _lvl.layer.masksToBounds = YES;
    _lvl.translatesAutoresizingMaskIntoConstraints = NO;
    _msg = [UILabel new]; _msg.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    _msg.textColor = [UIColor colorWithRed:0.88 green:0.88 blue:0.88 alpha:1];
    _msg.numberOfLines = 0; _msg.translatesAutoresizingMaskIntoConstraints = NO;
    [self.contentView addSubview:_ts]; [self.contentView addSubview:_lvl]; [self.contentView addSubview:_msg];
    [NSLayoutConstraint activateConstraints:@[
        [_ts.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:4],
        [_ts.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:8],
        [_lvl.centerYAnchor constraintEqualToAnchor:_ts.centerYAnchor],
        [_lvl.leadingAnchor constraintEqualToAnchor:_ts.trailingAnchor constant:5],
        [_lvl.widthAnchor constraintEqualToConstant:52], [_lvl.heightAnchor constraintEqualToConstant:14],
        [_msg.topAnchor constraintEqualToAnchor:_ts.bottomAnchor constant:2],
        [_msg.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:8],
        [_msg.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-8],
        [_msg.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-4],
    ]];
    return self;
}
- (void)configure:(LogEntry *)e {
    _ts.text = e.ts;
    _msg.text = [NSString stringWithFormat:@"[%@] %@", e.source, e.message];
    NSDictionary *p = @{
        @"HOOK":  @[[UIColor colorWithRed:0.47 green:0.75 blue:1.00 alpha:1], [UIColor colorWithRed:0.08 green:0.18 blue:0.32 alpha:1]],
        @"FOUND": @[[UIColor colorWithRed:0.30 green:0.95 blue:0.50 alpha:1], [UIColor colorWithRed:0.05 green:0.28 blue:0.10 alpha:1]],
        @"SPOOF": @[[UIColor colorWithRed:0.82 green:0.66 blue:1.00 alpha:1], [UIColor colorWithRed:0.20 green:0.10 blue:0.30 alpha:1]],
        @"INFO":  @[[UIColor colorWithWhite:0.55 alpha:1], [UIColor colorWithWhite:0.14 alpha:1]],
    };
    NSArray *pair = p[e.level] ?: p[@"INFO"];
    _lvl.text = e.level; _lvl.textColor = pair[0]; _lvl.backgroundColor = pair[1];
}
@end

@interface DHOverlay : UIWindow <UITableViewDataSource, UITableViewDelegate>
+ (instancetype)shared;
- (void)appendLevel:(NSString *)lv source:(NSString *)src message:(NSString *)msg;
@end

@implementation DHOverlay {
    UIView *_panel; UILabel *_stats; UITableView *_table; UIButton *_minBtn;
    NSMutableArray<LogEntry *> *_entries;
    NSMutableDictionary *_sourceCounts;
    NSString *_lastSpoof;
    BOOL _minimized;
}

+ (instancetype)shared {
    static DHOverlay *inst; static dispatch_once_t t;
    dispatch_once(&t, ^{
        inst = [[DHOverlay alloc] initWithFrame:UIScreen.mainScreen.bounds];
        inst.windowLevel = UIWindowLevelAlert + 100;
        inst.backgroundColor = UIColor.clearColor;
        inst->_entries = [NSMutableArray array];
        inst->_sourceCounts = [NSMutableDictionary dictionary];
        [inst buildUI]; inst.hidden = NO;
    });
    return inst;
}

- (void)buildUI {
    CGFloat W = UIScreen.mainScreen.bounds.size.width;
    _panel = [[UIView alloc] initWithFrame:CGRectMake(8, 60, W-16, 340)];
    _panel.backgroundColor    = [UIColor colorWithRed:0.04 green:0.04 blue:0.07 alpha:0.95];
    _panel.layer.cornerRadius = 14; _panel.layer.borderWidth = 0.5;
    _panel.layer.borderColor  = [UIColor colorWithWhite:0.28 alpha:0.5].CGColor;
    _panel.clipsToBounds = YES;

    UIView *bar = [[UIView alloc] initWithFrame:CGRectMake(0,0,W-16,38)];
    bar.backgroundColor = [UIColor colorWithRed:0.07 green:0.07 blue:0.11 alpha:1];
    UIView *handle = [[UIView alloc] initWithFrame:CGRectMake((W-16)/2-20,7,40,4)];
    handle.backgroundColor = [UIColor colorWithWhite:0.38 alpha:1]; handle.layer.cornerRadius = 2;
    [bar addSubview:handle];
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(12,17,W-80,16)];
    title.text = @"🎭 deviceId Hook + Spoof";
    title.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    title.textColor = [UIColor colorWithWhite:0.88 alpha:1]; [bar addSubview:title];
    _minBtn = [UIButton buttonWithType:UIButtonTypeCustom]; _minBtn.frame = CGRectMake(W-16-34,9,28,20);
    [_minBtn setTitle:@"−" forState:UIControlStateNormal];
    _minBtn.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightMedium];
    [_minBtn setTitleColor:[UIColor colorWithWhite:0.6 alpha:1] forState:UIControlStateNormal];
    [_minBtn addTarget:self action:@selector(toggleMin) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:_minBtn]; [_panel addSubview:bar];

    _stats = [[UILabel alloc] initWithFrame:CGRectMake(10,38,W-36,18)];
    _stats.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    _stats.textColor = [UIColor colorWithWhite:0.42 alpha:1];
    _stats.text = @"Başlatılıyor…"; [_panel addSubview:_stats];
    UIView *sep = [[UIView alloc] initWithFrame:CGRectMake(0,57,W-16,0.5)];
    sep.backgroundColor = [UIColor colorWithWhite:0.2 alpha:1]; [_panel addSubview:sep];

    _table = [[UITableView alloc] initWithFrame:CGRectMake(0,58,W-16,340-58-40)];
    _table.backgroundColor = UIColor.clearColor; _table.separatorStyle = UITableViewCellSeparatorStyleNone;
    _table.dataSource = self; _table.delegate = self;
    _table.rowHeight = UITableViewAutomaticDimension; _table.estimatedRowHeight = 48;
    [_table registerClass:[DHLogCell class] forCellReuseIdentifier:@"C"]; [_panel addSubview:_table];

    UIView *bot = [[UIView alloc] initWithFrame:CGRectMake(0,300,W-16,40)];
    bot.backgroundColor = [UIColor colorWithRed:0.05 green:0.05 blue:0.09 alpha:1];
    UIView *sep2 = [[UIView alloc] initWithFrame:CGRectMake(0,0,W-16,0.5)];
    sep2.backgroundColor = [UIColor colorWithWhite:0.18 alpha:1]; [bot addSubview:sep2];
    UIButton *clr = [UIButton buttonWithType:UIButtonTypeCustom]; clr.frame = CGRectMake(10,8,56,24);
    [clr setTitle:@"Temizle" forState:UIControlStateNormal];
    clr.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
    [clr setTitleColor:[UIColor colorWithWhite:0.42 alpha:1] forState:UIControlStateNormal];
    [clr addTarget:self action:@selector(clearLogs) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:clr];
    UIButton *cpy = [UIButton buttonWithType:UIButtonTypeCustom];
    cpy.tag = 99; cpy.frame = CGRectMake(W-16-88,6,80,28);
    [cpy setTitle:@"📋 Kopyala" forState:UIControlStateNormal];
    cpy.titleLabel.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    [cpy setTitleColor:[UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:1] forState:UIControlStateNormal];
    cpy.layer.borderWidth = 0.5; cpy.layer.cornerRadius = 6;
    cpy.layer.borderColor = [UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:0.4].CGColor;
    [cpy addTarget:self action:@selector(copyLogs) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:cpy]; [_panel addSubview:bot];
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    [bar addGestureRecognizer:pan]; [self addSubview:_panel];
}

- (void)appendLevel:(NSString *)lv source:(NSString *)src message:(NSString *)msg {
    LogEntry *e = [[LogEntry alloc] initLevel:lv source:src msg:msg];
    [_entries addObject:e];
    _sourceCounts[src] = @([_sourceCounts[src] integerValue] + 1);
    if ([lv isEqualToString:@"SPOOF"]) _lastSpoof = src;
    [self updateStats]; [_table reloadData];
    if (_entries.count > 0)
        [_table scrollToRowAtIndexPath:[NSIndexPath indexPathForRow:_entries.count-1 inSection:0]
                      atScrollPosition:UITableViewScrollPositionBottom animated:NO];
}

- (void)updateStats {
    NSMutableArray *p = [NSMutableArray array];
    NSArray *keys = @[@"PhotonIMUtils", @"NSStringUtils", @"Keychain-lm", @"PhotonIMAuthData"];
    for (NSString *k in keys)
        if (_sourceCounts[k]) [p addObject:[NSString stringWithFormat:@"%@:%@", k, _sourceCounts[k]]];
    if (_lastSpoof) [p addObject:[NSString stringWithFormat:@"✅spoof:%@", _lastSpoof]];
    _stats.text = p.count > 0 ? [p componentsJoinedByString:@" "] : @"Bekleniyor…";
}

- (void)clearLogs {
    [_entries removeAllObjects]; [_sourceCounts removeAllObjects]; _lastSpoof = nil;
    _stats.text = @"Temizlendi"; [_table reloadData];
}

- (void)copyLogs {
    NSMutableString *t = [NSMutableString string];
    for (LogEntry *e in _entries) [t appendFormat:@"[%@][%@][%@] %@\n", e.ts, e.level, e.source, e.message];
    [t appendFormat:@"\n=== FAKE deviceId ===\n%@\n", kFakeDeviceId];
    [UIPasteboard generalPasteboard].string = t;
    UIButton *b = (UIButton *)[_panel viewWithTag:99];
    NSString *orig = [b titleForState:UIControlStateNormal];
    [b setTitle:@"✅ Kopyalandı" forState:UIControlStateNormal];
    [b setTitleColor:[UIColor colorWithRed:0.30 green:0.95 blue:0.50 alpha:1] forState:UIControlStateNormal];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [b setTitle:orig forState:UIControlStateNormal];
        [b setTitleColor:[UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:1] forState:UIControlStateNormal];
    });
}
- (void)toggleMin {
    _minimized = !_minimized; CGRect f = _panel.frame; f.size.height = _minimized ? 38 : 340;
    [UIView animateWithDuration:0.2 animations:^{ self->_panel.frame = f; }];
    [_minBtn setTitle:_minimized ? @"+" : @"−" forState:UIControlStateNormal];
}
- (void)handlePan:(UIPanGestureRecognizer *)pan {
    CGPoint t = [pan translationInView:self]; CGRect f = _panel.frame, s = UIScreen.mainScreen.bounds;
    f.origin.x = MAX(0, MIN(f.origin.x+t.x, s.size.width-f.size.width));
    f.origin.y = MAX(20, MIN(f.origin.y+t.y, s.size.height-f.size.height-20));
    _panel.frame = f; [pan setTranslation:CGPointZero inView:self];
}
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return _entries.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    DHLogCell *c = [tv dequeueReusableCellWithIdentifier:@"C" forIndexPath:ip];
    [c configure:_entries[ip.row]]; return c;
}
@end

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Helpers
// ═══════════════════════════════════════════════════════════════════════════

static void hlog(NSString *lv, NSString *src, NSString *fmt, ...) NS_FORMAT_FUNCTION(3,4);
static void hlog(NSString *lv, NSString *src, NSString *fmt, ...) {
    va_list a; va_start(a, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:a]; va_end(a);
    NSLog(@"[DHook][%@][%@] %@", lv, src, msg);
    dispatch_async(logQ(), ^{
        dispatch_async(dispatch_get_main_queue(), ^{ [[DHOverlay shared] appendLevel:lv source:src message:msg]; });
    });
}

static void swiz(Class cls, SEL sel, IMP *orig, IMP newIMP) {
    Method m = class_getInstanceMethod(cls, sel) ?: class_getClassMethod(cls, sel);
    if (!m) return;
    *orig = method_getImplementation(m); method_setImplementation(m, newIMP);
    hlog(@"HOOK", @"Swizzle", @"✓ [%@ %@]", NSStringFromClass(cls), NSStringFromSelector(sel));
}

static void hookClass(NSString *name, SEL sel, IMP *orig, IMP newIMP) {
    Class cls = NSClassFromString(name); if (!cls) return;
    swiz(cls, sel, orig, newIMP);
}

// hex string → NSData
static NSData *hexToData(NSString *hex) {
    NSMutableData *d = [NSMutableData dataWithCapacity:hex.length/2];
    for (NSUInteger i = 0; i+1 < hex.length; i += 2) {
        unsigned int byte;
        [[NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(i,2)]] scanHexInt:&byte];
        uint8_t b = (uint8_t)byte; [d appendBytes:&b length:1];
    }
    return d;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hook Implementations
// ═══════════════════════════════════════════════════════════════════════════

// ── PhotonIMUtils +deviceID ───────────────────────────────────────────────
static IMP orig_photonDeviceID;
static id h_photonDeviceID(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_photonDeviceID)(self, _cmd);
    hlog(@"FOUND", @"PhotonIMUtils", @"+deviceID → %@", val);
    if (kSpoofEnabled) {
        hlog(@"SPOOF", @"PhotonIMUtils", @"→ %@", kFakeDeviceId);
        return kFakeDeviceId;
    }
    return val;
}

// ── NSStringUtils +deviceID ───────────────────────────────────────────────
static IMP orig_nsStringDeviceID;
static id h_nsStringDeviceID(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_nsStringDeviceID)(self, _cmd);
    hlog(@"FOUND", @"NSStringUtils", @"+deviceID → %@", val);
    if (kSpoofEnabled) {
        hlog(@"SPOOF", @"NSStringUtils", @"→ %@", kFakeDeviceId);
        return kFakeDeviceId;
    }
    return val;
}

// ── PhotonIMAuthData -deviceId getter ────────────────────────────────────
static IMP orig_authDataDeviceId;
static id h_authDataDeviceId(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_authDataDeviceId)(self, _cmd);
    hlog(@"FOUND", @"PhotonIMAuthData", @"-deviceId → %@", val);
    if (kSpoofEnabled) {
        hlog(@"SPOOF", @"PhotonIMAuthData", @"→ %@", kFakeDeviceId);
        return kFakeDeviceId;
    }
    return val;
}

// ── PhotonIMAuthData -setDeviceId: ───────────────────────────────────────
static IMP orig_setDeviceId;
static void h_setDeviceId(id self, SEL _cmd, id val) {
    hlog(@"FOUND", @"PhotonIMAuthData", @"-setDeviceId: ← %@", val);
    if (kSpoofEnabled) {
        hlog(@"SPOOF", @"PhotonIMAuthData", @"setDeviceId: ← fake");
        ((void(*)(id,SEL,id))orig_setDeviceId)(self, _cmd, kFakeDeviceId);
        return;
    }
    ((void(*)(id,SEL,id))orig_setDeviceId)(self, _cmd, val);
}

// ── DUSecretCollector +getUndergroundDeviceId: ───────────────────────────
// Bu method binary data alıp Base64/hex çıktı üretiyor.
// Spoof: fake hex'i binary'e çevirip veriyoruz.
static IMP orig_getUndergroundDeviceId;
static id h_getUndergroundDeviceId(id self, SEL _cmd, id arg) {
    id val = ((id(*)(id,SEL,id))orig_getUndergroundDeviceId)(self, _cmd, arg);
    hlog(@"FOUND", @"DUSecretCollector", @"+getUndergroundDeviceId → %@", val);
    if (kSpoofEnabled) {
        // Eğer çıktı string (Base64 veya hex) ise fake döndür
        if ([val isKindOfClass:[NSString class]]) {
            hlog(@"SPOOF", @"DUSecretCollector", @"+getUndergroundDeviceId → fake");
            return kFakeDeviceId;
        }
        // Binary data ise hex'i data'ya çevir
        if ([val isKindOfClass:[NSData class]]) {
            NSData *fakeData = hexToData(kFakeDeviceId);
            hlog(@"SPOOF", @"DUSecretCollector", @"+getUndergroundDeviceId → fake data (%lu bytes)", (unsigned long)fakeData.length);
            return fakeData;
        }
    }
    return val;
}

// ── DUSecretCollector +getMasterDeviceId: ────────────────────────────────
static IMP orig_getMasterDeviceId;
static id h_getMasterDeviceId(id self, SEL _cmd, id arg) {
    id val = ((id(*)(id,SEL,id))orig_getMasterDeviceId)(self, _cmd, arg);
    // Bu method çok sayıda farklı binary parça döndürüyor — kriptografik materyaller.
    // Sadece string çıktıyı spoof et, binary'lere dokunma (crash riski).
    if ([val isKindOfClass:[NSString class]]) {
        hlog(@"FOUND", @"DUSecretCollector", @"+getMasterDeviceId (str) → %@", val);
        if (kSpoofEnabled) {
            hlog(@"SPOOF", @"DUSecretCollector", @"+getMasterDeviceId → fake");
            return kFakeDeviceId;
        }
    }
    return val;
}

// ── NSUserDefaults — sadece loglama ──────────────────────────────────────
static IMP orig_udObjectForKey;
static id h_udObjectForKey(id self, SEL _cmd, NSString *key) {
    id val = ((id(*)(id,SEL,NSString*))orig_udObjectForKey)(self, _cmd, key);
    if (val && [key isEqualToString:@"kMATUserDefaultDeviceIDKey"])
        hlog(@"FOUND", @"NSUserDefaults", @"kMATUserDefaultDeviceIDKey → %@", val);
    return val;
}

// ── Keychain ─────────────────────────────────────────────────────────────
typedef OSStatus (*SecCopyFn)(CFDictionaryRef, CFTypeRef *);
static SecCopyFn orig_SecItemCopyMatching;

static OSStatus h_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *res) {
    OSStatus st = orig_SecItemCopyMatching(q, res);
    if (st != errSecSuccess || !res || !*res) return st;

    NSString *acc = (__bridge NSString *)CFDictionaryGetValue(q, kSecAttrAccount);
    NSString *svc = (__bridge NSString *)CFDictionaryGetValue(q, kSecAttrService);

    if ([acc isEqualToString:@"lm_new_device_deviceIdentifier"] ||
        [svc isEqualToString:@"lm_new_device_deviceIdentifier"]) {

        // Orijinali logla
        NSString *origStr = nil;
        CFTypeID tid = CFGetTypeID(*res);
        if (tid == CFDataGetTypeID()) {
            NSData *d = (__bridge NSData *)*res;
            origStr = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (!origStr) {
                // hex göster
                const uint8_t *b = d.bytes; NSMutableString *h = [NSMutableString string];
                for (NSUInteger i = 0; i < d.length; i++) [h appendFormat:@"%02x", b[i]];
                origStr = h;
            }
        } else if (tid == CFStringGetTypeID()) {
            origStr = (__bridge NSString *)*res;
        } else if (tid == CFDictionaryGetTypeID()) {
            NSData *d = ((__bridge NSDictionary *)*res)[(id)kSecValueData];
            if (d) { const uint8_t *b = d.bytes; NSMutableString *h = [NSMutableString string];
                for (NSUInteger i = 0; i < d.length; i++) [h appendFormat:@"%02x", b[i]]; origStr = h; }
        }
        hlog(@"FOUND", @"Keychain-lm", @"orijinal → %@", origStr ?: @"<nil>");

        if (!kSpoofEnabled) return st;

        // Spoof — fake hex'i binary data olarak yaz
        NSData *fakeData = hexToData(kFakeDeviceId);

        if (tid == CFDataGetTypeID()) {
            CFRelease(*res); *res = (__bridge_retained CFTypeRef)fakeData;
            hlog(@"SPOOF", @"Keychain-lm", @"→ %@ (%lu bytes)", kFakeDeviceId, (unsigned long)fakeData.length);
        } else if (tid == CFStringGetTypeID()) {
            CFRelease(*res); *res = (__bridge_retained CFTypeRef)kFakeDeviceId;
            hlog(@"SPOOF", @"Keychain-lm", @"(str) → %@", kFakeDeviceId);
        } else if (tid == CFDictionaryGetTypeID()) {
            NSMutableDictionary *d = [(__bridge NSDictionary *)*res mutableCopy];
            d[(id)kSecValueData] = fakeData;
            CFRelease(*res); *res = (__bridge_retained CFTypeRef)[d copy];
            hlog(@"SPOOF", @"Keychain-lm", @"(dict) → %@", kFakeDeviceId);
        }
    }
    return st;
}

typedef OSStatus (*SecAddFn)(CFDictionaryRef, CFTypeRef *);
static SecAddFn orig_SecItemAdd;
static OSStatus h_SecItemAdd(CFDictionaryRef attrs, CFTypeRef *res) {
    NSString *acc = (__bridge NSString *)CFDictionaryGetValue(attrs, kSecAttrAccount);
    if ([acc isEqualToString:@"lm_new_device_deviceIdentifier"] && kSpoofEnabled) {
        NSMutableDictionary *d = [(__bridge NSDictionary *)attrs mutableCopy];
        d[(id)kSecValueData] = hexToData(kFakeDeviceId);
        hlog(@"SPOOF", @"Keychain-lm", @"SecItemAdd → fake yazıldı");
        return orig_SecItemAdd((__bridge CFDictionaryRef)d, res);
    }
    return orig_SecItemAdd(attrs, res);
}

typedef OSStatus (*SecUpdateFn)(CFDictionaryRef, CFDictionaryRef);
static SecUpdateFn orig_SecItemUpdate;
static OSStatus h_SecItemUpdate(CFDictionaryRef q, CFDictionaryRef attrs) {
    NSString *acc = (__bridge NSString *)CFDictionaryGetValue(q, kSecAttrAccount);
    if ([acc isEqualToString:@"lm_new_device_deviceIdentifier"] && kSpoofEnabled) {
        NSMutableDictionary *d = [(__bridge NSDictionary *)attrs mutableCopy];
        d[(id)kSecValueData] = hexToData(kFakeDeviceId);
        hlog(@"SPOOF", @"Keychain-lm", @"SecItemUpdate → fake yazıldı");
        return orig_SecItemUpdate(q, (__bridge CFDictionaryRef)d);
    }
    return orig_SecItemUpdate(q, attrs);
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Constructor
// ═══════════════════════════════════════════════════════════════════════════

__attribute__((constructor))
static void init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [DHOverlay shared];
        hlog(@"INFO", @"dylib", @"Hook+Spoof — hazır | spoof:%@", kSpoofEnabled ? @"ON" : @"OFF");
        hlog(@"INFO", @"dylib", @"Fake: %@", kFakeDeviceId);

        // PhotonIMUtils +deviceID
        hookClass(@"PhotonIMUtils", @selector(deviceID), &orig_photonDeviceID, (IMP)h_photonDeviceID);

        // NSStringUtils +deviceID
        hookClass(@"NSStringUtils", @selector(deviceID), &orig_nsStringDeviceID, (IMP)h_nsStringDeviceID);

        // PhotonIMAuthData
        hookClass(@"PhotonIMAuthData", @selector(deviceId),     &orig_authDataDeviceId, (IMP)h_authDataDeviceId);
        hookClass(@"PhotonIMAuthData", @selector(setDeviceId:), &orig_setDeviceId,      (IMP)h_setDeviceId);

        // DUSecretCollector
        hookClass(@"DUSecretCollector", @selector(getUndergroundDeviceId:), &orig_getUndergroundDeviceId, (IMP)h_getUndergroundDeviceId);
        hookClass(@"DUSecretCollector", @selector(getMasterDeviceId:),      &orig_getMasterDeviceId,      (IMP)h_getMasterDeviceId);

        // NSUserDefaults (log only)
        swiz([NSUserDefaults class], @selector(objectForKey:), &orig_udObjectForKey, (IMP)h_udObjectForKey);

        // Keychain
        struct rebinding bindings[] = {
            {"SecItemCopyMatching", h_SecItemCopyMatching, (void**)&orig_SecItemCopyMatching},
            {"SecItemAdd",          h_SecItemAdd,          (void**)&orig_SecItemAdd},
            {"SecItemUpdate",       h_SecItemUpdate,       (void**)&orig_SecItemUpdate},
        };
        rebind_symbols(bindings, 3);
        hlog(@"HOOK", @"Keychain", @"✓ CopyMatching + Add + Update");

        hlog(@"INFO", @"dylib", @"Tüm hook'lar aktif");
    });
}
