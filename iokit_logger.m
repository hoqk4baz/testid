/*
 * LogWindow.dylib
 * ---------------
 * Keychain (SecItem*) ve CommonCrypto (CC_SHA256 / CCHmac) cagrilarini
 * fishhook ile yakalar; degerleri text + base64 olarak cihazda uygulamanin
 * ustunde acilan surukleneblir bir log penceresinde gosterir.
 *
 * Amac: deviceId/guid'in keychain'de nasil saklandigini ve hangi ham
 * sinyallerin hash'e girdigini GOZLEMLEMEK (Frida'siz, static injection).
 *
 * Derleme: GitHub Actions (bkz. .github/workflows/build-dylib.yml)
 * Inject : Sideloadly / TrollStore ile IPA'ya LC_LOAD_DYLIB olarak eklenir.
 */

#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import "fishhook.h"

/* ============================ LOG PENCERESI ============================ */

@interface LogWindow : UIWindow
@property (nonatomic, strong) UITextView *tv;
@property (nonatomic, strong) UILabel *header;
+ (instancetype)shared;
+ (void)post:(NSString *)s;
- (void)appendLine:(NSString *)s;
@end

static LogWindow *gWin = nil;

static UIWindowScene *activeScene(void) {
    UIApplication *app = UIApplication.sharedApplication;
    for (UIScene *s in app.connectedScenes) {
        if ([s isKindOfClass:UIWindowScene.class]) {
            UIWindowScene *ws = (UIWindowScene *)s;
            if (ws.activationState == UISceneActivationStateForegroundActive) return ws;
        }
    }
    for (UIScene *s in app.connectedScenes)
        if ([s isKindOfClass:UIWindowScene.class]) return (UIWindowScene *)s;
    return nil;
}

@implementation LogWindow

+ (instancetype)shared {
    if (gWin) return gWin;
    UIWindowScene *scene = activeScene();
    if (!scene) return nil;

    CGFloat w = UIScreen.mainScreen.bounds.size.width - 16.0;
    CGRect frame = CGRectMake(8, 70, w, 240);

    gWin = [[LogWindow alloc] initWithWindowScene:scene];
    gWin.frame = frame;
    gWin.windowLevel = UIWindowLevelAlert + 100;
    gWin.backgroundColor = [UIColor colorWithWhite:0 alpha:0.82];
    gWin.layer.cornerRadius = 10;
    gWin.clipsToBounds = YES;
    gWin.hidden = NO;

    // baslik / surukleme cubugu
    gWin.header = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, w, 26)];
    gWin.header.text = @"  KEYCHAIN/CRYPTO LOG  (basili tut+surukle)";
    gWin.header.textColor = [UIColor greenColor];
    gWin.header.font = [UIFont boldSystemFontOfSize:11];
    gWin.header.backgroundColor = [UIColor colorWithWhite:0 alpha:0.4];
    gWin.header.userInteractionEnabled = YES;
    [gWin addSubview:gWin.header];

    UIPanGestureRecognizer *pan =
        [[UIPanGestureRecognizer alloc] initWithTarget:gWin action:@selector(onPan:)];
    [gWin.header addGestureRecognizer:pan];

    // temizle butonu
    UIButton *clr = [UIButton buttonWithType:UIButtonTypeSystem];
    clr.frame = CGRectMake(w - 60, 0, 60, 26);
    [clr setTitle:@"temizle" forState:UIControlStateNormal];
    clr.titleLabel.font = [UIFont systemFontOfSize:11];
    [clr addTarget:gWin action:@selector(onClear) forControlEvents:UIControlEventTouchUpInside];
    [gWin addSubview:clr];

    // log alani
    gWin.tv = [[UITextView alloc] initWithFrame:CGRectMake(0, 26, w, frame.size.height - 26)];
    gWin.tv.editable = NO;
    gWin.tv.backgroundColor = [UIColor clearColor];
    gWin.tv.textColor = [UIColor colorWithRed:0.6 green:1 blue:0.6 alpha:1];
    gWin.tv.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
    [gWin addSubview:gWin.tv];

    return gWin;
}

- (void)onPan:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:self];
    self.center = CGPointMake(self.center.x + t.x, self.center.y + t.y);
    [g setTranslation:CGPointZero inView:self];
}

- (void)onClear { self.tv.text = @""; }

+ (void)post:(NSString *)s {
    LogWindow *w = [self shared];
    if (!w) {  // scene henuz hazir degil -> kisa gecikmeyle tekrar dene
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.7 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [LogWindow post:s]; });
        return;
    }
    [w appendLine:s];
}

- (void)appendLine:(NSString *)s {
    NSString *stamp = [NSString stringWithFormat:@"%.3f", CACurrentMediaTime()];
    self.tv.text = [self.tv.text stringByAppendingFormat:@"\n[%@] %@\n", stamp, s];
    NSRange end = NSMakeRange(self.tv.text.length, 0);
    [self.tv scrollRangeToVisible:end];
}

@end

/* pencereye + konsola log at */
static void LWLog(NSString *s) {
    NSLog(@"[LogWindow] %@", s);
    dispatch_async(dispatch_get_main_queue(), ^{ [LogWindow post:s]; });
}

/* ============================ YARDIMCILAR ============================ */

static NSString *describeCFValue(CFTypeRef val) {
    if (!val) return @"null";
    CFTypeID tid = CFGetTypeID(val);
    if (tid == CFDataGetTypeID()) {
        NSData *d = (__bridge NSData *)val;
        NSString *b64 = [d base64EncodedStringWithOptions:0];
        NSString *txt = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!txt) txt = @"<binary>";
        return [NSString stringWithFormat:@"len=%lu text=%@ b64=%@",
                (unsigned long)d.length, txt, b64];
    } else if (tid == CFStringGetTypeID()) {
        return (__bridge NSString *)val;
    }
    return @"<other-cftype>";
}

static NSString *dictStr(CFDictionaryRef dict, CFStringRef key) {
    if (!dict) return @"(nil-dict)";
    CFTypeRef v = CFDictionaryGetValue(dict, key);
    if (!v) return @"-";
    if (CFGetTypeID(v) == CFStringGetTypeID()) return (__bridge NSString *)v;
    return @"<non-string>";
}

static NSString *hmacName(CCHmacAlgorithm a) {
    switch (a) {
        case kCCHmacAlgSHA1:   return @"HMAC-SHA1";
        case kCCHmacAlgMD5:    return @"HMAC-MD5";
        case kCCHmacAlgSHA256: return @"HMAC-SHA256";
        case kCCHmacAlgSHA384: return @"HMAC-SHA384";
        case kCCHmacAlgSHA512: return @"HMAC-SHA512";
        case kCCHmacAlgSHA224: return @"HMAC-SHA224";
        default: return @"HMAC-?";
    }
}
static size_t hmacLen(CCHmacAlgorithm a) {
    switch (a) {
        case kCCHmacAlgSHA1: return 20; case kCCHmacAlgMD5: return 16;
        case kCCHmacAlgSHA256: return 32; case kCCHmacAlgSHA384: return 48;
        case kCCHmacAlgSHA512: return 64; case kCCHmacAlgSHA224: return 28;
        default: return 0;
    }
}

static NSString *bytesDesc(const void *p, size_t len) {
    if (!p || len == 0) return @"(empty)";
    NSData *d = [NSData dataWithBytes:p length:len];
    NSString *b64 = [d base64EncodedStringWithOptions:0];
    NSString *txt = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (!txt) txt = @"<binary>";
    return [NSString stringWithFormat:@"text=%@ b64=%@", txt, b64];
}

/* ============================ HOOK'LAR ============================ */

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus my_SecItemAdd(CFDictionaryRef query, CFTypeRef *result) {
    NSMutableString *m = [NSMutableString stringWithString:@"[SecItemAdd]"];
    [m appendFormat:@"\n  service: %@", dictStr(query, kSecAttrService)];
    [m appendFormat:@"\n  account: %@", dictStr(query, kSecAttrAccount)];
    CFTypeRef data = query ? CFDictionaryGetValue(query, kSecValueData) : NULL;
    [m appendFormat:@"\n  value:   %@", describeCFValue(data)];
    LWLog(m);
    return orig_SecItemAdd(query, result);
}

static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus my_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attrs) {
    NSMutableString *m = [NSMutableString stringWithString:@"[SecItemUpdate]"];
    [m appendFormat:@"\n  service: %@", dictStr(query, kSecAttrService)];
    [m appendFormat:@"\n  account: %@", dictStr(query, kSecAttrAccount)];
    CFTypeRef data = attrs ? CFDictionaryGetValue(attrs, kSecValueData) : NULL;
    [m appendFormat:@"\n  new:     %@", describeCFValue(data)];
    LWLog(m);
    return orig_SecItemUpdate(query, attrs);
}

static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus my_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus st = orig_SecItemCopyMatching(query, result);
    NSMutableString *m = [NSMutableString stringWithString:@"[SecItemCopyMatching]"];
    [m appendFormat:@"\n  service: %@", dictStr(query, kSecAttrService)];
    [m appendFormat:@"\n  account: %@", dictStr(query, kSecAttrAccount)];
    if (st == errSecSuccess && result && *result) {
        [m appendFormat:@"\n  returned: %@", describeCFValue(*result)];
    } else {
        [m appendFormat:@"\n  status:  %d", (int)st];
    }
    LWLog(m);
    return st;
}

static unsigned char *(*orig_CC_SHA256)(const void *, uint32_t, unsigned char *);
static unsigned char *my_CC_SHA256(const void *data, uint32_t len, unsigned char *md) {
    unsigned char *r = orig_CC_SHA256(data, len, md);
    NSMutableString *m = [NSMutableString stringWithString:@"[CC_SHA256]"];
    [m appendFormat:@"\n  input:  %@", bytesDesc(data, len)];
    [m appendFormat:@"\n  digest: %@", bytesDesc(md, CC_SHA256_DIGEST_LENGTH)];
    LWLog(m);
    return r;
}

static void (*orig_CCHmac)(CCHmacAlgorithm, const void *, size_t, const void *, size_t, void *);
static void my_CCHmac(CCHmacAlgorithm alg, const void *key, size_t keyLen,
                      const void *data, size_t dataLen, void *macOut) {
    orig_CCHmac(alg, key, keyLen, data, dataLen, macOut);
    NSMutableString *m = [NSMutableString stringWithFormat:@"[CCHmac %@]", hmacName(alg)];
    [m appendFormat:@"\n  key:    %@", bytesDesc(key, keyLen)];
    [m appendFormat:@"\n  input:  %@", bytesDesc(data, dataLen)];
    [m appendFormat:@"\n  mac:    %@", bytesDesc(macOut, hmacLen(alg))];
    LWLog(m);
}

/* ============================ KURULUM ============================ */

__attribute__((constructor))
static void init_logwindow(void) {
    struct rebinding rb[] = {
        { "SecItemAdd",          (void *)my_SecItemAdd,          (void **)&orig_SecItemAdd },
        { "SecItemUpdate",       (void *)my_SecItemUpdate,       (void **)&orig_SecItemUpdate },
        { "SecItemCopyMatching", (void *)my_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching },
        { "CC_SHA256",           (void *)my_CC_SHA256,           (void **)&orig_CC_SHA256 },
        { "CCHmac",              (void *)my_CCHmac,              (void **)&orig_CCHmac },
    };
    rebind_symbols(rb, sizeof(rb) / sizeof(rb[0]));
    LWLog(@"dylib yuklendi, hook'lar kuruldu");
}
