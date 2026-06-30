#import <UIKit/UIKit.h>
#import <Security/Security.h>

static UITextView *logView;
static NSMutableString *logs;

void AddLog(NSString *text) {
    NSString *line = [NSString stringWithFormat:@"[%@] %@\n",
                      [NSDate date], text];
    [logs appendString:line];
    dispatch_async(dispatch_get_main_queue(), ^{
        logView.text = logs;
    });
}

void ClearKeychain(void) {
    NSDictionary *query = @{(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword};
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

    AddLog([NSString stringWithFormat:@"Keychain cleared (%d)", (int)status]);
}

@interface DebugWindow : UIWindow
@end

@implementation DebugWindow
- (instancetype)init {
    self = [super initWithFrame:[UIScreen mainScreen].bounds];
    if (self) {
        logs = [NSMutableString new];

        UIViewController *vc = [UIViewController new];
        self.rootViewController = vc;
        self.windowLevel = UIWindowLevelAlert + 1;
        [self makeKeyAndVisible];

        logView = [[UITextView alloc] initWithFrame:CGRectMake(10, 50,
                                self.frame.size.width - 20,
                                self.frame.size.height - 100)];
        logView.editable = NO;
        [vc.view addSubview:logView];

        UIButton *copy = [UIButton buttonWithType:UIButtonTypeSystem];
        copy.frame = CGRectMake(10, 10, 80, 30);
        [copy setTitle:@"Copy" forState:UIControlStateNormal];
        [copy addTarget:self action:@selector(copyLogs) forControlEvents:UIControlEventTouchUpInside];
        [vc.view addSubview:copy];

        UIButton *clear = [UIButton buttonWithType:UIButtonTypeSystem];
        clear.frame = CGRectMake(100, 10, 80, 30);
        [clear setTitle:@"Clear" forState:UIControlStateNormal];
        [clear addTarget:self action:@selector(clearLogs) forControlEvents:UIControlEventTouchUpInside];
        [vc.view addSubview:clear];

        ClearKeychain();
        AddLog(@"App started");
    }
    return self;
}

- (void)copyLogs {
    UIPasteboard.generalPasteboard.string = logs;
    AddLog(@"Logs copied");
}

- (void)clearLogs {
    [logs setString:@""];
    logView.text = @"";
}
@end

__attribute__((constructor))
static void init() {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[DebugWindow alloc] init];
    });
}
