//
//  DeviceIdHook.m  — Log + Spoof (v3)
//  com.farah.chat (Amar)
//  Hedefler: Keychain + PhotonIMUtils + NSStringUtils + DUSecretCollector
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
#import <dlfcn.h>
#include "fishhook.h"

// ─── Ayarlar ─────────────────────────────────────────────────────────────
// Gerçek ID: 77bc647fc7ccc3aec3cd94eace776e68fc23b1661774527271fd (52 char hex)
static NSString *const kFakeDeviceId = @"00000000000000000000000000000000000000000000000000000000";
static BOOL kSpoofEnabled = YES;

// PhotonIMUtils +deviceID — fake döndür
static IMP orig_photonDeviceID;
static id h_photonDeviceID(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_photonDeviceID)(self, _cmd);
    hlog(@"FOUND", @"PhotonIMUtils", @"+deviceID orijinal → %@", val);
    if (kSpoofEnabled) {
        hlog(@"SPOOF", @"PhotonIMUtils", @"+deviceID → fake");
        return kFakeDeviceId;
    }
    return val;
}

// constructor içine ekle:
hookClass(@"PhotonIMUtils", @selector(deviceID), &orig_photonDeviceID, (IMP)h_photonDeviceID);

// ─── Log queue ───────────────────────────────────────────────────────────
static dispatch_queue_t logQ(void) {
    static dispatch_queue_t q; static dispatch_once_t t;
    dispatch_once(&t, ^{ q = dispatch_queue_create("dhook.log", DISPATCH_QUEUE_SERIAL); });
    return q;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Log Entry & Cell
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

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Overlay
// ═══════════════════════════════════════════════════════════════════════════

@interface DHOverlay : UIWindow <UITableViewDataSource, UITableViewDelegate>
+ (instancetype)shared;
- (void)appendLevel:(NSString *)lv source:(NSString *)src message:(NSString *)msg;
@end

@implementation DHOverlay {
    UIView *_panel; UILabel *_stats; UITableView *_table; UIButton *_minBtn;
    NSMutableArray<LogEntry *> *_entries;
    NSMutableDictionary *_spoofed; // kaynak → spoof sayısı
    BOOL _minimized;
}

+ (instancetype)shared {
    static DHOverlay *inst; static dispatch_once_t t;
    dispatch_once(&t, ^{
        inst = [[DHOverlay alloc] initWithFrame:UIScreen.mainScreen.bounds];
        inst.windowLevel = UIWindowLevelAlert + 100;
        inst.backgroundColor = UIColor.clearColor;
        inst->_entries = [NSMutableArray array];
        inst->_spoofed = [NSMutableDictionary dictionary];
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
    title.text = kSpoofEnabled ? @"🎭 deviceId Spoof v3" : @"🔍 deviceId Log";
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
    if ([lv isEqualToString:@"SPOOF"])
        _spoofed[src] = @([_spoofed[src] integerValue] + 1);
    [self updateStats]; [_table reloadData];
    if (_entries.count > 0)
        [_table scrollToRowAtIndexPath:[NSIndexPath indexPathForRow:_entries.count-1 inSection:0]
                      atScrollPosition:UITableViewScrollPositionBottom animated:NO];
}

- (void)updateStats {
    if (_spoofed.count == 0) { _stats.text = @"Bekleniyor…"; return; }
    NSMutableArray *p = [NSMutableArray array];
    [_spoofed enumerateKeysAndObjectsUsingBlock:^(NSString *k, NSNumber *v, BOOL *s){
        [p addObject:[NSString stringWithFormat:@"%@✕%@", k, v]];
    }];
    _stats.text = [@"SPOOF: " stringByAppendingString:[p componentsJoinedByString:@" "]];
}

- (void)clearLogs {
    [_entries removeAllObjects]; [_spoofed removeAllObjects];
    _stats.text = @"Temizlendi"; [_table reloadData];
}
- (void)copyLogs {
    NSMutableString *t = [NSMutableString string];
    for (LogEntry *e in _entries) [t appendFormat:@"[%@][%@][%@] %@\n", e.ts, e.level, e.source, e.message];
    [t appendFormat:@"\nFake ID: %@\n", kFakeDeviceId];
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
// MARK: - Global helpers
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

static void hookClass(NSString *clsName, SEL sel, IMP *orig, IMP newIMP) {
    Class cls = NSClassFromString(clsName);
    if (!cls) { hlog(@"INFO", @"Hook", @"Class yok: %@", clsName); return; }
    swiz(cls, sel, orig, newIMP);
}

// 52 char hex'i NSData'ya çevir (Keychain binary format için)
static NSData *hexToData(NSString *hex) {
    NSMutableData *d = [NSMutableData dataWithCapacity:hex.length/2];
    for (NSUInteger i = 0; i+1 < hex.length; i += 2) {
        unsigned int byte;
        [[NSScanner scannerWithString:[hex substringWithRange:NSMakeRange(i,2)]] scanHexInt:&byte];
        uint8_t b = (uint8_t)byte;
        [d appendBytes:&b length:1];
    }
    return d;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hook: PhotonIMUtils +deviceID
// ═══════════════════════════════════════════════════════════════════════════

static IMP orig_photonDeviceID;
static id h_photonDeviceID(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_photonDeviceID)(self, _cmd);
    hlog(@"FOUND", @"PhotonIMUtils", @"+deviceID orijinal → %@", val);
    if (kSpoofEnabled) {
        hlog(@"SPOOF", @"PhotonIM", @"+deviceID → fake");
        return kFakeDeviceId;
    }
    return val;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hook: NSStringUtils +deviceID
// ═══════════════════════════════════════════════════════════════════════════

static IMP orig_nsStringDeviceID;
static id h_nsStringDeviceID(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_nsStringDeviceID)(self, _cmd);
    hlog(@"FOUND", @"NSStringUtils", @"+deviceID orijinal → %@", val);
    if (kSpoofEnabled) {
        hlog(@"SPOOF", @"NSStringUtils", @"+deviceID → fake");
        return kFakeDeviceId;
    }
    return val;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hook: PhotonIMAuthData -setDeviceId:
// ═══════════════════════════════════════════════════════════════════════════

static IMP orig_setDeviceId;
static void h_setDeviceId(id self, SEL _cmd, id val) {
    hlog(@"FOUND", @"PhotonIMAuthData", @"-setDeviceId: ← %@", val);
    if (kSpoofEnabled) {
        hlog(@"SPOOF", @"PhotonIMAuthData", @"-setDeviceId: → fake");
        ((void(*)(id,SEL,id))orig_setDeviceId)(self, _cmd, kFakeDeviceId);
        return;
    }
    ((void(*)(id,SEL,id))orig_setDeviceId)(self, _cmd, val);
}

static IMP orig_getDeviceId;
static id h_getDeviceId(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_getDeviceId)(self, _cmd);
    if (val) hlog(@"FOUND", @"PhotonIMAuthData", @"-deviceId → %@", val);
    if (kSpoofEnabled && val) {
        hlog(@"SPOOF", @"PhotonIMAuthData", @"-deviceId → fake");
        return kFakeDeviceId;
    }
    return val;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hook: DUSecretCollector +getUndergroundDeviceId:
// ═══════════════════════════════════════════════════════════════════════════

static IMP orig_getUnderground;
static id h_getUnderground(id self, SEL _cmd, id arg) {
    id val = ((id(*)(id,SEL,id))orig_getUnderground)(self, _cmd, arg);
    hlog(@"FOUND", @"DUSecretCollector", @"+getUndergroundDeviceId orijinal → %@", val);
    if (kSpoofEnabled) {
        hlog(@"SPOOF", @"DUSec", @"+getUndergroundDeviceId → fake");
        return kFakeDeviceId;
    }
    return val;
}

static IMP orig_getMaster;
static id h_getMaster(id self, SEL _cmd, id arg) {
    id val = ((id(*)(id,SEL,id))orig_getMaster)(self, _cmd, arg);
    // getMaster binary data döndürüyor — sadece logla
    hlog(@"FOUND", @"DUSecretCollector", @"+getMasterDeviceId → %@", val);
    return val;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hook: NSUserDefaults (kMATUserDefaultDeviceIDKey)
// ═══════════════════════════════════════════════════════════════════════════

static IMP orig_udObjectForKey;
static id h_udObjectForKey(id self, SEL _cmd, NSString *key) {
    id val = ((id(*)(id,SEL,NSString*))orig_udObjectForKey)(self, _cmd, key);
    if ([key isEqualToString:@"kMATUserDefaultDeviceIDKey"] && val)
        hlog(@"FOUND", @"NSUserDefaults", @"kMATUserDefaultDeviceIDKey → %@", val);
    return val;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hook: Keychain
// ═══════════════════════════════════════════════════════════════════════════

typedef OSStatus (*SecCopyFn)(CFDictionaryRef, CFTypeRef *);
static SecCopyFn orig_SecItemCopyMatching;

static OSStatus h_SecItemCopyMatching(CFDictionaryRef q, CFTypeRef *res) {
    OSStatus st = orig_SecItemCopyMatching(q, res);
    if (st != errSecSuccess || !res || !*res) return st;

    NSString *acc = (__bridge NSString *)CFDictionaryGetValue(q, kSecAttrAccount);
    NSString *svc = (__bridge NSString *)CFDictionaryGetValue(q, kSecAttrService);

    BOOL isTarget = [acc isEqualToString:@"lm_new_device_deviceIdentifier"] ||
                    [svc isEqualToString:@"lm_new_device_deviceIdentifier"];

    if (!isTarget) return st;

    // Orijinali logla
    NSString *origStr = nil;
    CFTypeID tid = CFGetTypeID(*res);
    if (tid == CFDataGetTypeID()) {
        NSData *d = (__bridge NSData *)*res;
        origStr = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!origStr) {
            // Hex dump
            const uint8_t *bytes = d.bytes;
            NSMutableString *hex = [NSMutableString string];
            for (NSUInteger i = 0; i < MIN(d.length, 32); i++) [hex appendFormat:@"%02x", bytes[i]];
            origStr = [NSString stringWithFormat:@"<hex:%@>", hex];
        }
    } else if (tid == CFStringGetTypeID()) {
        origStr = (__bridge NSString *)*res;
    } else if (tid == CFDictionaryGetTypeID()) {
        NSData *d = ((__bridge NSDictionary *)*res)[(id)kSecValueData];
        if (d) origStr = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!origStr) origStr = @"<dict/binary>";
    }
    hlog(@"FOUND", @"Keychain-lm", @"orijinal → %@", origStr ?: @"<binary>");

    if (!kSpoofEnabled) return st;

    // Spoof — hem string hem binary dene
    NSData *fakeData = hexToData(kFakeDeviceId); // binary format
    NSString *fakeStr = kFakeDeviceId;           // string format

    if (tid == CFDataGetTypeID()) {
        CFRelease(*res);
        *res = (__bridge_retained CFTypeRef)fakeData;
        hlog(@"SPOOF", @"Keychain-lm", @"(data) → fake");
    } else if (tid == CFStringGetTypeID()) {
        CFRelease(*res);
        *res = (__bridge_retained CFTypeRef)fakeStr;
        hlog(@"SPOOF", @"Keychain-lm", @"(str) → fake");
    } else if (tid == CFDictionaryGetTypeID()) {
        NSMutableDictionary *d = [(__bridge NSDictionary *)*res mutableCopy];
        d[(id)kSecValueData] = fakeData;
        CFRelease(*res);
        *res = (__bridge_retained CFTypeRef)[d copy];
        hlog(@"SPOOF", @"Keychain-lm", @"(dict) → fake");
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
        hlog(@"INFO", @"dylib", @"deviceId Spoof v3 — hazır");
        hlog(@"INFO", @"dylib", @"Fake ID: %@", kFakeDeviceId);
        hlog(@"INFO", @"dylib", @"Spoof: %@", kSpoofEnabled ? @"AKTİF" : @"KAPALI");

        // ObjC swizzle'lar
        hookClass(@"PhotonIMUtils",    @selector(deviceID),      &orig_photonDeviceID, (IMP)h_photonDeviceID);
        hookClass(@"NSStringUtils",    @selector(deviceID),      &orig_nsStringDeviceID, (IMP)h_nsStringDeviceID);
        hookClass(@"PhotonIMAuthData", @selector(setDeviceId:),  &orig_setDeviceId, (IMP)h_setDeviceId);
        hookClass(@"PhotonIMAuthData", @selector(deviceId),      &orig_getDeviceId, (IMP)h_getDeviceId);
        hookClass(@"DUSecretCollector",@selector(getUndergroundDeviceId:), &orig_getUnderground, (IMP)h_getUnderground);
        hookClass(@"DUSecretCollector",@selector(getMasterDeviceId:),      &orig_getMaster,      (IMP)h_getMaster);
        hookClass(@"mlamdfndogdaf",    @selector(getUndergroundDeviceId:), &orig_getUnderground, (IMP)h_getUnderground);
        swiz([NSUserDefaults class], @selector(objectForKey:), &orig_udObjectForKey, (IMP)h_udObjectForKey);

        // C function hook'ları (fishhook)
        struct rebinding bindings[] = {
            {"SecItemCopyMatching", h_SecItemCopyMatching, (void**)&orig_SecItemCopyMatching},
            {"SecItemAdd",          h_SecItemAdd,          (void**)&orig_SecItemAdd},
            {"SecItemUpdate",       h_SecItemUpdate,       (void**)&orig_SecItemUpdate},
        };
        rebind_symbols(bindings, 3);
        hlog(@"HOOK", @"Keychain", @"✓ SecItemCopyMatching + Add + Update");

        hlog(@"INFO", @"dylib", @"Tüm hook'lar aktif — uygulamayı kullan");
        hlog(@"INFO", @"dylib", @"SPOOF loglarını izle, hangisi ateşlenmiyor dikkat et");
    });
}
