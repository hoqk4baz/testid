#import <UIKit/UIKit.h>
#import <Security/Security.h>

static UIWindow *debugWindow;
static UITextView *logView;
static NSMutableString *logs;

#pragma mark - Logger

void AddLog(NSString *text) {
    if (!logs) logs = [NSMutableString new];

    NSString *line = [NSString stringWithFormat:@"[%@] %@\n",
                      [NSDateFormatter localizedStringFromDate:[NSDate date]
                                                     dateStyle:NSDateFormatterNoStyle
                                                     timeStyle:NSDateFormatterMediumStyle],
                      text];

    [logs appendString:line];

    dispatch_async(dispatch_get_main_queue(), ^{
        logView.text = logs;
    });

    NSLog(@"%@", text);
}

#pragma mark - Keychain Reset

void ResetKeychainClass(id secClass, NSString *name) {

    NSDictionary *query = @{
        (__bridge id)kSecClass: secClass
    };

    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

    if (status == errSecSuccess || status == errSecItemNotFound) {
        AddLog([NSString stringWithFormat:@"✔ %@ cleared", name]);
    } else {
        AddLog([NSString stringWithFormat:@"✖ %@ failed (%d)", name, (int)status]);
    }
}

void ResetAllKeychain(void) {

    AddLog(@"Starting Keychain reset...");

    ResetKeychainClass((__bridge id)kSecClassGenericPassword, @"GenericPassword");
    ResetKeychainClass((__bridge id)kSecClassInternetPassword, @"InternetPassword");
    ResetKeychainClass((__bridge id)kSecClassCertificate, @"Certificate");
    ResetKeychainClass((__bridge id)kSecClassKey, @"Key");
    ResetKeychainClass((__bridge id)kSecClassIdentity, @"Identity");

    AddLog(@"Keychain reset finished");
}

#pragma mark - UI

@interface DebugVC : UIViewController
@end

@implementation DebugVC

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = [UIColor blackColor];

    logView = [[UITextView alloc] initWithFrame:CGRectMake(10, 60,
                self.view.frame.size.width - 20,
                self.view.frame.size.height - 120)];

    logView.backgroundColor = [UIColor colorWithWhite:0.1 alpha:1];
    logView.textColor = [UIColor greenColor];
    logView.editable = NO;

    [self.view addSubview:logView];

    UIButton *copy = [UIButton buttonWithType:UIButtonTypeSystem];
    copy.frame = CGRectMake(10, 20, 80, 30);
    [copy setTitle:@"Copy" forState:UIControlStateNormal];
    [copy addTarget:self action:@selector(copyLogs) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:copy];

    UIButton *clear = [UIButton buttonWithType:UIButtonTypeSystem];
    clear.frame = CGRectMake(100, 20, 80, 30);
    [clear setTitle:@"Clear" forState:UIControlStateNormal];
    [clear addTarget:self action:@selector(clearLogs) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:clear];

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        ResetAllKeychain();
    });
}

- (void)copyLogs {
    UIPasteboard.generalPasteboard.string = logs;
    AddLog(@"Logs copied to clipboard");
}

- (void)clearLogs {
    [logs setString:@""];
    logView.text = @"";
}

@end

#pragma mark - Window

void ShowDebugWindow(void) {

    dispatch_async(dispatch_get_main_queue(), ^{

        debugWindow = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        debugWindow.windowLevel = UIWindowLevelAlert + 100;

        debugWindow.rootViewController = [DebugVC new];
        [debugWindow makeKeyAndVisible];

        AddLog(@"Debug window started");
    });
}

#pragma mark - Entry

__attribute__((constructor))
static void init() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        ShowDebugWindow();
        AddLog(@"App initialized");
    });
}
