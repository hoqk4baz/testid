//
//  DeviceIdHook.m  — HTTP Header intercept + spoof
//  deviceId header'ı setValue:forHTTPHeaderField: anında değiştir
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

// ─── Fake deviceId — orijinalle aynı format (52 hex char) ────────────────
static NSString *const kFakeDeviceId = @"aabbccddeeff00112233445566778899aabbccddeeff00112233";
static BOOL kSpoofEnabled = YES;

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
    self = [super init]; NSDateFormatter *f = [NSDateFormatter new]; f.dateFormat = @"HH:mm:ss.SSS";
    self.ts = [f stringFromDate:[NSDate date]]; self.level=lv; self.source=src; self.message=msg;
    return self;
}
@end

@interface DHLogCell : UITableViewCell - (void)configure:(LogEntry *)e; @end
@implementation DHLogCell { UILabel *_ts, *_lvl, *_msg; }
- (instancetype)initWithStyle:(UITableViewCellStyle)s reuseIdentifier:(NSString *)r {
    self = [super initWithStyle:s reuseIdentifier:r];
    self.backgroundColor = UIColor.clearColor; self.selectionStyle = UITableViewCellSelectionStyleNone;
    _ts=[UILabel new]; _ts.font=[UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    _ts.textColor=[UIColor colorWithWhite:0.4 alpha:1]; _ts.translatesAutoresizingMaskIntoConstraints=NO;
    _lvl=[UILabel new]; _lvl.font=[UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightBold];
    _lvl.textAlignment=NSTextAlignmentCenter; _lvl.layer.cornerRadius=3; _lvl.layer.masksToBounds=YES;
    _lvl.translatesAutoresizingMaskIntoConstraints=NO;
    _msg=[UILabel new]; _msg.font=[UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    _msg.textColor=[UIColor colorWithRed:0.88 green:0.88 blue:0.88 alpha:1];
    _msg.numberOfLines=0; _msg.translatesAutoresizingMaskIntoConstraints=NO;
    [self.contentView addSubview:_ts]; [self.contentView addSubview:_lvl]; [self.contentView addSubview:_msg];
    [NSLayoutConstraint activateConstraints:@[
        [_ts.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:4],
        [_ts.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:8],
        [_lvl.centerYAnchor constraintEqualToAnchor:_ts.centerYAnchor],
        [_lvl.leadingAnchor constraintEqualToAnchor:_ts.trailingAnchor constant:5],
        [_lvl.widthAnchor constraintEqualToConstant:52],[_lvl.heightAnchor constraintEqualToConstant:14],
        [_msg.topAnchor constraintEqualToAnchor:_ts.bottomAnchor constant:2],
        [_msg.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:8],
        [_msg.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-8],
        [_msg.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-4],
    ]]; return self;
}
- (void)configure:(LogEntry *)e {
    _ts.text=e.ts; _msg.text=[NSString stringWithFormat:@"[%@] %@", e.source, e.message];
    NSDictionary *p = @{
        @"FOUND": @[[UIColor colorWithRed:0.30 green:0.95 blue:0.50 alpha:1],[UIColor colorWithRed:0.05 green:0.28 blue:0.10 alpha:1]],
        @"SPOOF": @[[UIColor colorWithRed:0.82 green:0.66 blue:1.00 alpha:1],[UIColor colorWithRed:0.20 green:0.10 blue:0.30 alpha:1]],
        @"HOOK":  @[[UIColor colorWithRed:0.47 green:0.75 blue:1.00 alpha:1],[UIColor colorWithRed:0.08 green:0.18 blue:0.32 alpha:1]],
        @"INFO":  @[[UIColor colorWithWhite:0.55 alpha:1],[UIColor colorWithWhite:0.14 alpha:1]],
    };
    NSArray *pair = p[e.level] ?: p[@"INFO"];
    _lvl.text=e.level; _lvl.textColor=pair[0]; _lvl.backgroundColor=pair[1];
}
@end

@interface DHOverlay : UIWindow <UITableViewDataSource, UITableViewDelegate>
+ (instancetype)shared;
- (void)appendLevel:(NSString *)lv source:(NSString *)src message:(NSString *)msg;
@end

@implementation DHOverlay {
    UIView *_panel; UILabel *_stats; UITableView *_table; UIButton *_minBtn;
    NSMutableArray<LogEntry *> *_entries; BOOL _minimized;
    NSUInteger _spoofCount;
}
+ (instancetype)shared {
    static DHOverlay *i; static dispatch_once_t t;
    dispatch_once(&t, ^{
        i=[[DHOverlay alloc] initWithFrame:UIScreen.mainScreen.bounds];
        i.windowLevel=UIWindowLevelAlert+100; i.backgroundColor=UIColor.clearColor;
        i->_entries=[NSMutableArray array]; [i buildUI]; i.hidden=NO;
    }); return i;
}
- (void)buildUI {
    CGFloat W=UIScreen.mainScreen.bounds.size.width;
    _panel=[[UIView alloc] initWithFrame:CGRectMake(8,60,W-16,340)];
    _panel.backgroundColor=[UIColor colorWithRed:0.04 green:0.04 blue:0.07 alpha:0.95];
    _panel.layer.cornerRadius=14; _panel.layer.borderWidth=0.5;
    _panel.layer.borderColor=[UIColor colorWithWhite:0.28 alpha:0.5].CGColor; _panel.clipsToBounds=YES;

    UIView *bar=[[UIView alloc] initWithFrame:CGRectMake(0,0,W-16,38)];
    bar.backgroundColor=[UIColor colorWithRed:0.07 green:0.07 blue:0.11 alpha:1];
    UIView *h=[[UIView alloc] initWithFrame:CGRectMake((W-16)/2-20,7,40,4)];
    h.backgroundColor=[UIColor colorWithWhite:0.38 alpha:1]; h.layer.cornerRadius=2; [bar addSubview:h];
    UILabel *ttl=[[UILabel alloc] initWithFrame:CGRectMake(12,17,W-80,16)];
    ttl.text=kSpoofEnabled ? @"🎭 deviceId Spoof — Header" : @"📡 deviceId Tracer";
    ttl.font=[UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    ttl.textColor=[UIColor colorWithWhite:0.88 alpha:1]; [bar addSubview:ttl];
    _minBtn=[UIButton buttonWithType:UIButtonTypeCustom]; _minBtn.frame=CGRectMake(W-16-34,9,28,20);
    [_minBtn setTitle:@"−" forState:UIControlStateNormal];
    _minBtn.titleLabel.font=[UIFont systemFontOfSize:15 weight:UIFontWeightMedium];
    [_minBtn setTitleColor:[UIColor colorWithWhite:0.6 alpha:1] forState:UIControlStateNormal];
    [_minBtn addTarget:self action:@selector(toggleMin) forControlEvents:UIControlEventTouchUpInside];
    [bar addSubview:_minBtn]; [_panel addSubview:bar];

    _stats=[[UILabel alloc] initWithFrame:CGRectMake(10,38,W-36,18)];
    _stats.font=[UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightRegular];
    _stats.textColor=[UIColor colorWithWhite:0.42 alpha:1]; _stats.text=@"Bekleniyor…"; [_panel addSubview:_stats];
    UIView *sep=[[UIView alloc] initWithFrame:CGRectMake(0,57,W-16,0.5)];
    sep.backgroundColor=[UIColor colorWithWhite:0.2 alpha:1]; [_panel addSubview:sep];

    _table=[[UITableView alloc] initWithFrame:CGRectMake(0,58,W-16,340-58-40)];
    _table.backgroundColor=UIColor.clearColor; _table.separatorStyle=UITableViewCellSeparatorStyleNone;
    _table.dataSource=self; _table.delegate=self;
    _table.rowHeight=UITableViewAutomaticDimension; _table.estimatedRowHeight=48;
    [_table registerClass:[DHLogCell class] forCellReuseIdentifier:@"C"]; [_panel addSubview:_table];

    UIView *bot=[[UIView alloc] initWithFrame:CGRectMake(0,300,W-16,40)];
    bot.backgroundColor=[UIColor colorWithRed:0.05 green:0.05 blue:0.09 alpha:1];
    UIView *sep2=[[UIView alloc] initWithFrame:CGRectMake(0,0,W-16,0.5)];
    sep2.backgroundColor=[UIColor colorWithWhite:0.18 alpha:1]; [bot addSubview:sep2];
    UIButton *clr=[UIButton buttonWithType:UIButtonTypeCustom]; clr.frame=CGRectMake(10,8,56,24);
    [clr setTitle:@"Temizle" forState:UIControlStateNormal];
    clr.titleLabel.font=[UIFont systemFontOfSize:11 weight:UIFontWeightMedium];
    [clr setTitleColor:[UIColor colorWithWhite:0.42 alpha:1] forState:UIControlStateNormal];
    [clr addTarget:self action:@selector(clearLogs) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:clr];
    UIButton *cpy=[UIButton buttonWithType:UIButtonTypeCustom]; cpy.tag=99;
    cpy.frame=CGRectMake(W-16-88,6,80,28);
    [cpy setTitle:@"📋 Kopyala" forState:UIControlStateNormal];
    cpy.titleLabel.font=[UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
    [cpy setTitleColor:[UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:1] forState:UIControlStateNormal];
    cpy.layer.borderWidth=0.5; cpy.layer.cornerRadius=6;
    cpy.layer.borderColor=[UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:0.4].CGColor;
    [cpy addTarget:self action:@selector(copyLogs) forControlEvents:UIControlEventTouchUpInside];
    [bot addSubview:cpy]; [_panel addSubview:bot];
    UIPanGestureRecognizer *pan=[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(handlePan:)];
    [bar addGestureRecognizer:pan]; [self addSubview:_panel];
}

// Panel dışına tıklanınca touch'u app'e geçir
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *hit = [super hitTest:point withEvent:event];
    return (hit == self) ? nil : hit;
}
- (void)appendLevel:(NSString *)lv source:(NSString *)src message:(NSString *)msg {
    LogEntry *e=[[LogEntry alloc] initLevel:lv source:src msg:msg];
    [_entries addObject:e];
    if ([lv isEqualToString:@"SPOOF"]) {
        _spoofCount++;
        _stats.text=[NSString stringWithFormat:@"✅ Spoof aktif — %lu istek değiştirildi", (unsigned long)_spoofCount];
    }
    [_table reloadData];
    if (_entries.count>0)
        [_table scrollToRowAtIndexPath:[NSIndexPath indexPathForRow:_entries.count-1 inSection:0]
                      atScrollPosition:UITableViewScrollPositionBottom animated:NO];
}
- (void)clearLogs { [_entries removeAllObjects]; _spoofCount=0; _stats.text=@"Temizlendi"; [_table reloadData]; }
- (void)copyLogs {
    NSMutableString *t=[NSMutableString string];
    for (LogEntry *e in _entries) [t appendFormat:@"[%@][%@][%@] %@\n",e.ts,e.level,e.source,e.message];
    [t appendFormat:@"\n=== FAKE deviceId ===\n%@\n",kFakeDeviceId];
    [UIPasteboard generalPasteboard].string=t;
    UIButton *b=(UIButton *)[_panel viewWithTag:99]; NSString *o=[b titleForState:UIControlStateNormal];
    [b setTitle:@"✅ Kopyalandı" forState:UIControlStateNormal];
    [b setTitleColor:[UIColor colorWithRed:0.30 green:0.95 blue:0.50 alpha:1] forState:UIControlStateNormal];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.5*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
        [b setTitle:o forState:UIControlStateNormal];
        [b setTitleColor:[UIColor colorWithRed:0.47 green:0.75 blue:1.0 alpha:1] forState:UIControlStateNormal];
    });
}
- (void)toggleMin {
    _minimized=!_minimized; CGRect f=_panel.frame; f.size.height=_minimized?38:340;
    [UIView animateWithDuration:0.2 animations:^{self->_panel.frame=f;}];
    [_minBtn setTitle:_minimized?@"+":@"−" forState:UIControlStateNormal];
}
- (void)handlePan:(UIPanGestureRecognizer *)pan {
    CGPoint t=[pan translationInView:self]; CGRect f=_panel.frame,s=UIScreen.mainScreen.bounds;
    f.origin.x=MAX(0,MIN(f.origin.x+t.x,s.size.width-f.size.width));
    f.origin.y=MAX(20,MIN(f.origin.y+t.y,s.size.height-f.size.height-20));
    _panel.frame=f; [pan setTranslation:CGPointZero inView:self];
}
- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return _entries.count; }
- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    DHLogCell *c=[tv dequeueReusableCellWithIdentifier:@"C" forIndexPath:ip];
    [c configure:_entries[ip.row]]; return c;
}
@end

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Helpers
// ═══════════════════════════════════════════════════════════════════════════

static void hlog(NSString *lv, NSString *src, NSString *fmt, ...) NS_FORMAT_FUNCTION(3,4);
static void hlog(NSString *lv, NSString *src, NSString *fmt, ...) {
    va_list a; va_start(a,fmt);
    NSString *msg=[[NSString alloc] initWithFormat:fmt arguments:a]; va_end(a);
    NSLog(@"[DHook][%@][%@] %@",lv,src,msg);
    dispatch_async(logQ(), ^{
        dispatch_async(dispatch_get_main_queue(), ^{
            [[DHOverlay shared] appendLevel:lv source:src message:msg];
        });
    });
}

static void swiz(Class cls, SEL sel, IMP *orig, IMP newIMP) {
    Method m=class_getInstanceMethod(cls,sel)?:class_getClassMethod(cls,sel);
    if (!m) return; *orig=method_getImplementation(m); method_setImplementation(m,newIMP);
    hlog(@"HOOK",@"Swizzle",@"✓ [%@ %@]",NSStringFromClass(cls),NSStringFromSelector(sel));
}

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Hooks: her yerde kFakeDeviceId ile değiştir
// ═══════════════════════════════════════════════════════════════════════════

static NSString *const kTargetId = @"77bc647fc7ccc3aec3cd94eace776e68fc23b1661774527271fd";

// Bir string içinde hedef ID varsa değiştir
static NSString *replaceId(NSString *s) {
    if (!s || ![s isKindOfClass:[NSString class]]) return s;
    if ([s containsString:kTargetId])
        return [s stringByReplacingOccurrencesOfString:kTargetId withString:kFakeDeviceId];
    return s;
}

// Data içinde hedef ID varsa değiştir
static NSData *replaceIdInData(NSData *data) {
    if (!data) return data;
    NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!s) return data;
    NSString *replaced = replaceId(s);
    if (replaced == s) return data; // değişmedi
    hlog(@"SPOOF", @"Body", @"body içinde deviceId değiştirildi");
    return [replaced dataUsingEncoding:NSUTF8StringEncoding];
}

// ── 1. Header ─────────────────────────────────────────────────────────────
static IMP orig_setValue_forHTTPHeaderField;
static void h_setValue_forHTTPHeaderField(id self, SEL _cmd, NSString *val, NSString *field) {
    if (kSpoofEnabled && [val isKindOfClass:[NSString class]] && [val containsString:kTargetId]) {
        hlog(@"FOUND", @"Header", @"%@: %@", field, val);
        val = replaceId(val);
        hlog(@"SPOOF", @"Header", @"%@: %@", field, val);
    }
    ((void(*)(id,SEL,NSString*,NSString*))orig_setValue_forHTTPHeaderField)(self,_cmd,val,field);
}

// ── 2. URL (query string) ─────────────────────────────────────────────────
static IMP orig_setURL;
static void h_setURL(id self, SEL _cmd, NSURL *url) {
    if (kSpoofEnabled && url) {
        NSString *abs = url.absoluteString;
        if ([abs containsString:kTargetId]) {
            hlog(@"FOUND", @"URL", @"%@", abs);
            NSString *replaced = replaceId(abs);
            url = [NSURL URLWithString:replaced];
            hlog(@"SPOOF", @"URL", @"%@", replaced);
        }
    }
    ((void(*)(id,SEL,NSURL*))orig_setURL)(self,_cmd,url);
}

// ── 3. HTTP Body ──────────────────────────────────────────────────────────
static IMP orig_setHTTPBody;
static void h_setHTTPBody(id self, SEL _cmd, NSData *body) {
    if (kSpoofEnabled && body) {
        NSData *replaced = replaceIdInData(body);
        if (replaced != body) body = replaced;
    }
    ((void(*)(id,SEL,NSData*))orig_setHTTPBody)(self,_cmd,body);
}

// ── 4. HTTP Body Stream (multipart gibi durumlarda) ───────────────────────
// Stream hook zor, body yeterliyse atla

// ═══════════════════════════════════════════════════════════════════════════
// MARK: - Constructor
// ═══════════════════════════════════════════════════════════════════════════

__attribute__((constructor))
static void init(void) {
    // Hook'ları hemen kur — uygulama açılır açılmaz giden istekleri yakala
    // 1. Header
    swiz([NSMutableURLRequest class],
         @selector(setValue:forHTTPHeaderField:),
         &orig_setValue_forHTTPHeaderField,
         (IMP)h_setValue_forHTTPHeaderField);

    // 2. URL query string
    swiz([NSMutableURLRequest class],
         @selector(setURL:),
         &orig_setURL,
         (IMP)h_setURL);

    // 3. HTTP Body
    swiz([NSMutableURLRequest class],
         @selector(setHTTPBody:),
         &orig_setHTTPBody,
         (IMP)h_setHTTPBody);

    // Overlay UI ana thread hazır olunca kur (geç olabilir, hook'lar zaten aktif)
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [DHOverlay shared];
        hlog(@"INFO",@"dylib",@"deviceId Spoof — hazır");
        hlog(@"INFO",@"dylib",@"Hedef: %@", kTargetId);
        hlog(@"INFO",@"dylib",@"Fake : %@", kFakeDeviceId);
        hlog(@"INFO",@"dylib",@"Hook'lar constructor'da kuruldu ✅");
    });
}
