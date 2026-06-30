#import <UIKit/UIKit.h>
#import <Security/Security.h>

static UIWindow *window;
static UIView *panel;
static UITextView *logView;
static NSMutableString *logs;

#pragma mark - LOG

void AddLog(NSString *text) {
    if (!logs) logs = [NSMutableString new];

    NSString *line = [NSString stringWithFormat:@"• %@\n", text];
    [logs appendString:line];

    dispatch_async(dispatch_get_main_queue(), ^{
        logView.text = logs;
    });

    NSLog(@"%@", text);
}

#pragma mark - KEYCHAIN RESET

void ClearKC(id cls, NSString *name) {
    NSDictionary *q = @{(__bridge id)kSecClass: cls};

    OSStatus s = SecItemDelete((__bridge CFDictionaryRef)q);

    if (s == errSecSuccess || s == errSecItemNotFound)
        AddLog([NSString stringWithFormat:@"✔ %@", name]);
    else
        AddLog([NSString stringWithFormat:@"✖ %@ (%d)", name, (int)s]);
}

void ResetKeychain(void) {
    AddLog(@"Keychain reset started");

    ClearKC((__bridge id)kSecClassGenericPassword, @"GenericPassword");
    ClearKC((__bridge id)kSecClassInternetPassword, @"InternetPassword");
    ClearKC((__bridge id)kSecClassCertificate, @"Certificate");
    ClearKC((__bridge id)kSecClassKey, @"Key");
    ClearKC((__bridge id)kSecClassIdentity, @"Identity");

    AddLog(@"Keychain reset finished");
}

#pragma mark - ACTIONS

@interface ActionHandler : NSObject
@end

@implementation ActionHandler

+ (void)copyLogs {
    UIPasteboard.generalPasteboard.string = logs;
    AddLog(@"Copied");
}

+ (void)clearLogs {
    [logs setString:@""];
    logView.text = @"";
    AddLog(@"Cleared");
}

@end

#pragma mark - DRAG VIEW

@interface DragView : UIView
@end

@implementation DragView {
    CGPoint startPoint;
}

- (void)touchesBegan:(NSSet *)touches withEvent:(UIEvent *)event {
    startPoint = [[touches anyObject] locationInView:self];
}

- (void)touchesMoved:(NSSet *)touches withEvent:(UIEvent *)event {
    CGPoint p = [[touches anyObject] locationInView:self.superview];

    CGRect f = self.frame;
    f.origin.x = p.x - startPoint.x;
    f.origin.y = p.y - startPoint.y;
    self.frame = f;
}

@end

#pragma mark - UI

void ShowFloating(void) {

    dispatch_async(dispatch_get_main_queue(), ^{

        // IMPORTANT: Normal level -> app touch'ları bloklamaz
        window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        window.windowLevel = UIWindowLevelNormal + 1;
        window.backgroundColor = UIColor.clearColor;

        UIViewController *vc = [UIViewController new];
        vc.view.backgroundColor = UIColor.clearColor;
        vc.view.userInteractionEnabled = YES;

        window.rootViewController = vc;
        [window makeKeyAndVisible];

        // PANEL
        panel = [[DragView alloc] initWithFrame:CGRectMake(40, 120, 260, 220)];
        panel.backgroundColor = [UIColor colorWithWhite:0.1 alpha:0.92];
        panel.layer.cornerRadius = 12;
        panel.userInteractionEnabled = YES;

        [vc.view addSubview:panel];

        // LOG VIEW
        logView = [[UITextView alloc] initWithFrame:CGRectMake(10, 10, 240, 150)];
        logView.backgroundColor = UIColor.clearColor;
        logView.textColor = UIColor.greenColor;
        logView.font = [UIFont systemFontOfSize:11];
        logView.editable = NO;
        logView.userInteractionEnabled = YES;

        [panel addSubview:logView];

        // COPY
        UIButton *copy = [UIButton buttonWithType:UIButtonTypeSystem];
        copy.frame = CGRectMake(10, 170, 60, 30);
        [copy setTitle:@"Copy" forState:UIControlStateNormal];
        [copy addTarget:[ActionHandler class]
                 action:@selector(copyLogs)
       forControlEvents:UIControlEventTouchUpInside];

        [panel addSubview:copy];

        // CLEAR
        UIButton *clear = [UIButton buttonWithType:UIButtonTypeSystem];
        clear.frame = CGRectMake(80, 170, 60, 30);
        [clear setTitle:@"Clear" forState:UIControlStateNormal];
        [clear addTarget:[ActionHandler class]
                  action:@selector(clearLogs)
        forControlEvents:UIControlEventTouchUpInside];

        [panel addSubview:clear];

        AddLog(@"Floating debug ready");

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
                       dispatch_get_main_queue(), ^{
            ResetKeychain();
        });
    });
}

#pragma mark - ENTRY

__attribute__((constructor))
static void init() {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        ShowFloating();
        AddLog(@"App started");
    });
}
