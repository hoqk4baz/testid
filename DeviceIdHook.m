//
//  DeviceIdHook.m  — Targeted hooks based on class scan results
//  com.farah.chat (Amar) — iOS 26, Flutter + ObjC hybrid
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

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Log queue (recursive-lock safe)
// ═══════════════════════════════════════════════════════════════════════════

static dispatch_queue_t logQ(void) {
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
    NSDateFormatter *f = [NSDateFormatter new]; f.dateFormat = @"HH:mm:ss.SSS";
    self.ts = [f stringFromDate:[NSDate date]]; self.level = lv; self.source = src; self.message = msg;
    return self;
}
@end

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Log Cell
// ═══════════════════════════════════════════════════════════════════════════

@interface DHLogCell : UITableViewCell
- (void)configure:(LogEntry *)e;
@end
@implementation DHLogCell { UILabel *_ts, *_lvl, *_msg; }
- (instancetype)initWithStyle:(UITableViewCellStyle)s reuseIdentifier:(NSString *)r {
    self = [super initWithStyle:s reuseIdentifier:r];
    self.backgroundColor = UIColor.clearColor; self.selectionStyle = UITableViewCellSelectionStyleNone;
    _ts  = [UILabel new]; _ts.font  = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
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
        @"HOOK":   @[[UIColor colorWithRed:0.47 green:0.75 blue:1.00 alpha:1], [UIColor colorWithRed:0.08 green:0.18 blue:0.32 alpha:1]],
        @"FOUND":  @[[UIColor colorWithRed:0.30 green:0.95 blue:0.50 alpha:1], [UIColor colorWithRed:0.05 green:0.28 blue:0.10 alpha:1]],
        @"SPOOF":  @[[UIColor colorWithRed:0.82 green:0.66 blue:1.00 alpha:1], [UIColor colorWithRed:0.20 green:0.10 blue:0.30 alpha:1]],
        @"STACK":  @[[UIColor colorWithRed:1.00 green:0.65 blue:0.40 alpha:1], [UIColor colorWithRed:0.30 green:0.14 blue:0.04 alpha:1]],
        @"INFO":   @[[UIColor colorWithWhite:0.55 alpha:1], [UIColor colorWithWhite:0.14 alpha:1]],
    };
    NSArray *pair = p[e.level] ?: p[@"INFO"];
    _lvl.text = e.level; _lvl.textColor = pair[0]; _lvl.backgroundColor = pair[1];
}
@end

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Overlay Window
// ═══════════════════════════════════════════════════════════════════════════

@interface DHOverlay : UIWindow <UITableViewDataSource, UITableViewDelegate>
+ (instancetype)shared;
- (void)appendLevel:(NSString *)lv source:(NSString *)src message:(NSString *)msg;
@end

@implementation DHOverlay {
    UIView *_panel; UILabel *_stats; UITableView *_table; UIButton *_minBtn;
    NSMutableArray<LogEntry *> *_entries; NSMutableDictionary *_counts;
    NSString *_detectedId; BOOL _minimized;
}

+ (instancetype)shared {
    static DHOverlay *inst; static dispatch_once_t t;
    dispatch_once(&t, ^{
        inst = [[DHOverlay alloc] initWithFrame:UIScreen.mainScreen.bounds];
        inst.windowLevel = UIWindowLevelAlert + 100;
        inst.backgroundColor = UIColor.clearColor;
        inst->_entries = [NSMutableArray array];
        inst->_counts  = [NSMutableDictionary dictionary];
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
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(12,17,W-70,16)];
    title.text = @"🔍 deviceId Hook — Targeted"; title.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
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
    _stats.text = @"Hook'lar yükleniyor…"; [_panel addSubview:_stats];

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
    NSAssert([NSThread isMainThread], @"must be main");
    LogEntry *e = [[LogEntry alloc] initLevel:lv source:src msg:msg];
    [_entries addObject:e];
    if (src) _counts[src] = @([_counts[src] integerValue] + 1);
    if ([lv isEqualToString:@"FOUND"] || [lv isEqualToString:@"SPOOF"]) {
        NSRange r = [msg rangeOfString:@"→ "];
        if (r.location != NSNotFound)
            _detectedId = [[[msg substringFromIndex:r.location+2] componentsSeparatedByString:@"\n"] firstObject];
    }
    [self updateStats]; [_table reloadData];
    if (_entries.count > 0)
        [_table scrollToRowAtIndexPath:[NSIndexPath indexPathForRow:_entries.count-1 inSection:0]
                      atScrollPosition:UITableViewScrollPositionBottom animated:NO];
}

- (void)updateStats {
    NSMutableArray *p = [NSMutableArray array];
    [_counts enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *s){ [p addObject:[NSString stringWithFormat:@"%@:%@",k,v]]; }];
    if (_detectedId.length > 0) [p addObject:[NSString stringWithFormat:@"id=%.16s…", _detectedId.UTF8String]];
    _stats.text = p.count > 0 ? [p componentsJoinedByString:@"  "] : @"Bekleniyor…";
}

- (void)clearLogs { [_entries removeAllObjects]; [_counts removeAllObjects]; _detectedId = nil; _stats.text = @"Temizlendi"; [_table reloadData]; }

- (void)copyLogs {
    NSMutableString *t = [NSMutableString string];
    for (LogEntry *e in _entries) [t appendFormat:@"[%@][%@][%@] %@\n", e.ts, e.level, e.source, e.message];
    if (_detectedId) [t appendFormat:@"\n=== TESPİT EDİLEN deviceId ===\n%@\n", _detectedId];
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
// MARK: - Global log helper
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

static NSString *appStack(void) {
    NSString *exe = [NSBundle mainBundle].executablePath.lastPathComponent;
    NSMutableArray *f = [NSMutableArray array];
    for (NSString *fr in [NSThread callStackSymbols])
        if ([fr containsString:exe] && f.count < 5) [f addObject:fr];
    return f.count > 0 ? [f componentsJoinedByString:@"\n    "] : @"(C/Flutter layer)";
}

static void swiz(Class cls, SEL sel, IMP *orig, IMP newIMP) {
    Method m = class_getInstanceMethod(cls, sel) ?: class_getClassMethod(cls, sel);
    if (!m) { hlog(@"INFO",@"Swizzle",@"Bulunamadı: [%@ %@]", NSStringFromClass(cls), NSStringFromSelector(sel)); return; }
    *orig = method_getImplementation(m); method_setImplementation(m, newIMP);
    hlog(@"HOOK",@"Swizzle",@"✓ [%@ %@]", NSStringFromClass(cls), NSStringFromSelector(sel));
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - TARGETED HOOKS (scan sonuçlarına göre)
// ═══════════════════════════════════════════════════════════════════════════

// ── 1. DUSecretCollector ─────────────────────────────────────────────────
// +getUndergroundDeviceId:  +getMasterDeviceId:  — en şüpheli kaynak
static IMP orig_getUndergroundDeviceId;
static id h_getUndergroundDeviceId(id self, SEL _cmd, id arg) {
    id val = ((id(*)(id,SEL,id))orig_getUndergroundDeviceId)(self, _cmd, arg);
    hlog(@"FOUND", @"DUSecretCollector", @"+getUndergroundDeviceId → %@\n    %@", val, appStack());
    return val;
}

static IMP orig_getMasterDeviceId;
static id h_getMasterDeviceId(id self, SEL _cmd, id arg) {
    id val = ((id(*)(id,SEL,id))orig_getMasterDeviceId)(self, _cmd, arg);
    hlog(@"FOUND", @"DUSecretCollector", @"+getMasterDeviceId → %@\n    %@", val, appStack());
    return val;
}

// ── 2. PhotonIMUtils ─────────────────────────────────────────────────────
// +deviceID  — PhotonIM SDK'sının device ID'si
static IMP orig_photonDeviceID;
static id h_photonDeviceID(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_photonDeviceID)(self, _cmd);
    hlog(@"FOUND", @"PhotonIMUtils", @"+deviceID → %@\n    %@", val, appStack());
    return val;
}

// ── 3. NSStringUtils ─────────────────────────────────────────────────────
static IMP orig_nsStringDeviceID;
static id h_nsStringDeviceID(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_nsStringDeviceID)(self, _cmd);
    hlog(@"FOUND", @"NSStringUtils", @"+deviceID → %@\n    %@", val, appStack());
    return val;
}

// ── 4. PhotonIMAuthData ───────────────────────────────────────────────────
// -deviceId getter — PhotonIM auth objesinin içindeki değer
static IMP orig_authDataDeviceId;
static id h_authDataDeviceId(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_authDataDeviceId)(self, _cmd);
    hlog(@"FOUND", @"PhotonIMAuthData", @"-deviceId → %@\n    %@", val, appStack());
    return val;
}

// -setDeviceId: — hangi değer set ediliyor?
static IMP orig_authDataSetDeviceId;
static void h_authDataSetDeviceId(id self, SEL _cmd, id newVal) {
    hlog(@"FOUND", @"PhotonIMAuthData", @"-setDeviceId: ← %@\n    %@", newVal, appStack());
    ((void(*)(id,SEL,id))orig_authDataSetDeviceId)(self, _cmd, newVal);
}

// ── 5. MATDeviceInfo ─────────────────────────────────────────────────────
static IMP orig_matDeviceIDString;
static id h_matDeviceIDString(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_matDeviceIDString)(self, _cmd);
    hlog(@"FOUND", @"MATDeviceInfo", @"-deviceIDString → %@\n    %@", val, appStack());
    return val;
}

static IMP orig_matGetDeviceIdString;
static id h_matGetDeviceIdString(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_matGetDeviceIdString)(self, _cmd);
    hlog(@"FOUND", @"MATDeviceInfo", @"-getDeviceIdString → %@\n    %@", val, appStack());
    return val;
}

// ── 6. RifleUtility / RifleEngine ────────────────────────────────────────
static IMP orig_rifleDeviceId;
static id h_rifleDeviceId(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_rifleDeviceId)(self, _cmd);
    hlog(@"FOUND", @"RifleUtility", @"+deviceId → %@\n    %@", val, appStack());
    return val;
}

static IMP orig_rifleEngineDeviceId;
static id h_rifleEngineDeviceId(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_rifleEngineDeviceId)(self, _cmd);
    hlog(@"FOUND", @"RifleEngine", @"+RifleDeviceId → %@\n    %@", val, appStack());
    return val;
}

// ── 7. DUUAID / DUAID ────────────────────────────────────────────────────
static IMP orig_duuaidSerial;
static id h_duuaidSerial(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_duuaidSerial)(self, _cmd);
    hlog(@"FOUND", @"DUUAID", @"-getSerialStr → %@\n    %@", val, appStack());
    return val;
}

// ── 8. MMXFileConfiguration ──────────────────────────────────────────────
// Bu class'ın deviceId property'si var
static IMP orig_mmxDeviceId;
static id h_mmxDeviceId(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_mmxDeviceId)(self, _cmd);
    if (val) hlog(@"FOUND", @"MMXFileConfig", @"-deviceId → %@\n    %@", val, appStack());
    return val;
}

// ── 9. AliyunIdentityLogger ──────────────────────────────────────────────
static IMP orig_aliyunDeviceId;
static id h_aliyunDeviceId(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_aliyunDeviceId)(self, _cmd);
    if (val) hlog(@"FOUND", @"AliyunIdentityLogger", @"-deviceId → %@\n    %@", val, appStack());
    return val;
}

// ── 10. DTFMobileIdentifier ──────────────────────────────────────────────
// deviceFingerprint + shareIdentifier
static IMP orig_dtfFingerprint;
static id h_dtfFingerprint(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_dtfFingerprint)(self, _cmd);
    if (val) hlog(@"FOUND", @"DTFMobileIdentifier", @"-deviceFingerprint → %@\n    %@", val, appStack());
    return val;
}
static IMP orig_dtfShareId;
static id h_dtfShareId(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_dtfShareId)(self, _cmd);
    if (val) hlog(@"FOUND", @"DTFMobileIdentifier", @"+shareIdentifier → %@\n    %@", val, appStack());
    return val;
}

// ── 11. mlamdfndogdaf (obfuscated) ───────────────────────────────────────
static IMP orig_mlamUnderground;
static id h_mlamUnderground(id self, SEL _cmd, id arg) {
    id val = ((id(*)(id,SEL,id))orig_mlamUnderground)(self, _cmd, arg);
    hlog(@"FOUND", @"mlamdfndogdaf", @"+getUndergroundDeviceId → %@\n    %@", val, appStack());
    return val;
}
static IMP orig_mlamMaster;
static id h_mlamMaster(id self, SEL _cmd, id arg) {
    id val = ((id(*)(id,SEL,id))orig_mlamMaster)(self, _cmd, arg);
    hlog(@"FOUND", @"mlamdfndogdaf", @"+getMasterDeviceId → %@\n    %@", val, appStack());
    return val;
}

// ── 12. MKFDTManager ─────────────────────────────────────────────────────
static IMP orig_mkfdtDeviceId;
static id h_mkfdtDeviceId(id self, SEL _cmd) {
    id val = ((id(*)(id,SEL))orig_mkfdtDeviceId)(self, _cmd);
    if (val) hlog(@"FOUND", @"MKFDTManager", @"-deviceId → %@\n    %@", val, appStack());
    return val;
}

// ── 13. NSUserDefaults (geniş ağ) ────────────────────────────────────────
static IMP orig_udObjectForKey, orig_udStringForKey;
static id h_udObjectForKey(id self, SEL _cmd, NSString *key) {
    id val = ((id(*)(id,SEL,NSString*))orig_udObjectForKey)(self, _cmd, key);
    if (val && ([key.lowercaseString containsString:@"deviceid"] ||
                [key.lowercaseString containsString:@"device_id"] ||
                [key.lowercaseString isEqualToString:@"udid"])) {
        hlog(@"FOUND", @"NSUserDefaults", @"key=\"%@\" → %@\n    %@", key, val, appStack());
    }
    return val;
}
static id h_udStringForKey(id self, SEL _cmd, NSString *key) {
    id val = ((id(*)(id,SEL,NSString*))orig_udStringForKey)(self, _cmd, key);
    if (val && ([key.lowercaseString containsString:@"deviceid"] ||
                [key.lowercaseString containsString:@"device_id"])) {
        hlog(@"FOUND", @"NSUserDefaults", @"stringKey=\"%@\" → %@\n    %@", key, val, appStack());
    }
    return val;
}

// ── 14. UIDevice IDFV ────────────────────────────────────────────────────
static IMP orig_idfv;
static NSUUID *h_idfv(id self, SEL _cmd) {
    NSUUID *u = ((NSUUID*(*)(id,SEL))orig_idfv)(self, _cmd);
    hlog(@"FOUND", @"IDFV", @"identifierForVendor → %@\n    %@", u.UUIDString, appStack());
    return u;
}

// ── 15. Keychain ─────────────────────────────────────────────────────────
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
        NSString *label = acc ?: svc ?: @"";
        BOOL interesting = val.length >= 32 || [label.lowercaseString containsString:@"device"] || [label.lowercaseString containsString:@"id"];
        hlog(interesting ? @"FOUND" : @"INFO", @"Keychain",
             @"account=\"%@\" svc=\"%@\" → %@\n    %@",
             acc?:@"-", svc?:@"-", val?:@"<binary>", appStack());
    }
    return st;
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Constructor
// ═══════════════════════════════════════════════════════════════════════════

static void hookClass(NSString *clsName, SEL sel, IMP *orig, IMP newIMP) {
    Class cls = NSClassFromString(clsName);
    if (!cls) { hlog(@"INFO",@"Swizzle",@"Class bulunamadı: %@", clsName); return; }
    swiz(cls, sel, orig, newIMP);
}

__attribute__((constructor))
static void init(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [DHOverlay shared];
        hlog(@"INFO", @"dylib", @"Targeted deviceId Hook — hazır");
        hlog(@"INFO", @"dylib", @"com.farah.chat (Amar) — scan sonuçlarına göre %d hedef hook", 15);

        // DUSecretCollector
        hookClass(@"DUSecretCollector", @selector(getUndergroundDeviceId:), &orig_getUndergroundDeviceId, (IMP)h_getUndergroundDeviceId);
        hookClass(@"DUSecretCollector", @selector(getMasterDeviceId:),      &orig_getMasterDeviceId,      (IMP)h_getMasterDeviceId);

        // mlamdfndogdaf (obfuscated DUSecretCollector alias)
        hookClass(@"mlamdfndogdaf", @selector(getUndergroundDeviceId:), &orig_mlamUnderground, (IMP)h_mlamUnderground);
        hookClass(@"mlamdfndogdaf", @selector(getMasterDeviceId:),      &orig_mlamMaster,      (IMP)h_mlamMaster);

        // PhotonIM SDK
        hookClass(@"PhotonIMUtils",     @selector(deviceID),      &orig_photonDeviceID,      (IMP)h_photonDeviceID);
        hookClass(@"PhotonIMAuthData",  @selector(deviceId),      &orig_authDataDeviceId,    (IMP)h_authDataDeviceId);
        hookClass(@"PhotonIMAuthData",  @selector(setDeviceId:),  &orig_authDataSetDeviceId, (IMP)h_authDataSetDeviceId);

        // NSStringUtils
        hookClass(@"NSStringUtils", @selector(deviceID), &orig_nsStringDeviceID, (IMP)h_nsStringDeviceID);

        // MATDeviceInfo
        hookClass(@"MATDeviceInfo", @selector(deviceIDString),    &orig_matDeviceIDString,    (IMP)h_matDeviceIDString);
        hookClass(@"MATDeviceInfo", @selector(getDeviceIdString), &orig_matGetDeviceIdString, (IMP)h_matGetDeviceIdString);

        // Rifle SDK
        hookClass(@"RifleUtility", @selector(deviceId),      &orig_rifleDeviceId,       (IMP)h_rifleDeviceId);
        hookClass(@"RifleEngine",  @selector(RifleDeviceId), &orig_rifleEngineDeviceId, (IMP)h_rifleEngineDeviceId);

        // DUUAID
        hookClass(@"DUUAID", @selector(getSerialStr), &orig_duuaidSerial, (IMP)h_duuaidSerial);

        // MMXFileConfiguration
        hookClass(@"MMXFileConfiguration", @selector(deviceId), &orig_mmxDeviceId, (IMP)h_mmxDeviceId);

        // AliyunIdentityLogger
        hookClass(@"AliyunIdentityLogger", @selector(deviceId), &orig_aliyunDeviceId, (IMP)h_aliyunDeviceId);

        // DTFMobileIdentifier
        hookClass(@"DTFMobileIdentifier", @selector(deviceFingerprint), &orig_dtfFingerprint, (IMP)h_dtfFingerprint);
        hookClass(@"DTFMobileIdentifier", @selector(shareIdentifier),   &orig_dtfShareId,     (IMP)h_dtfShareId);

        // MKFDTManager
        hookClass(@"MKFDTManager", @selector(deviceId), &orig_mkfdtDeviceId, (IMP)h_mkfdtDeviceId);

        // NSUserDefaults (filtrelenmiş)
        swiz([NSUserDefaults class], @selector(objectForKey:), &orig_udObjectForKey, (IMP)h_udObjectForKey);
        swiz([NSUserDefaults class], @selector(stringForKey:), &orig_udStringForKey, (IMP)h_udStringForKey);

        // UIDevice IDFV
        swiz([UIDevice class], @selector(identifierForVendor), &orig_idfv, (IMP)h_idfv);

        // Keychain
        struct rebinding kb[] = {{"SecItemCopyMatching", h_SecItemCopyMatching, (void**)&orig_SecItemCopyMatching}};
        rebind_symbols(kb, 1);
        hlog(@"HOOK", @"Keychain", @"✓ SecItemCopyMatching hooked");

        hlog(@"INFO", @"dylib", @"Tüm hook'lar aktif — uygulamayı kullan, logları izle");
    });
}
