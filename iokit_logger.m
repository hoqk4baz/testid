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

#pragma mark - KEYCHAIN CLEAN

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

    AddLog(@"Keychain reset done");
}

#pragma mark - DRAG

@interface DragView : UIView
@end

@implementation DragView {
    CGPoint start;
}

- (void)touchesBegan:(NSSet *)touches withEvent:(UIEvent *)event {
    start = [[touches anyObject] locationInView:self];
}

- (void)touchesMoved:(NSSet *)touches withEvent:(UIEvent *)event {
    CGPoint p = [[touches anyObject] locationInView:self.superview];

    CGRect f = self.frame;
    f.origin.x = p.x - start.x;
    f.origin.y = p.y - start.y;

    self.frame = f;
}

@end

#pragma mark - UI

void ShowFloating(void) {

    dispatch_async(dispatch_get_main_queue(), ^{

        window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        window.windowLevel = UIWindowLevelAlert + 1;
        window.backgroundColor = UIColor.clearColor;
        window.rootViewController = [UIViewController new];
        window.hidden = NO;
        [window makeKeyAndVisible];

        // küçük panel
        panel = [[DragView alloc] initWithFrame:CGRectMake(20, 100, 260, 220)];
        panel.backgroundColor = [UIColor colorWithWhite:0.1 alpha:0.95];
        panel.layer.cornerRadius = 12;
        panel.clipsToBounds = YES;

        [window.rootViewController.view addSubview:panel];

        // log view
        logView = [[UITextView alloc] initWithFrame:CGRectMake(10, 10, 240, 150)];
        logView.backgroundColor = UIColor.clearColor;
        logView.textColor = UIColor.greenColor;
        logView.font = [UIFont systemFontOfSize:11];
        logView.editable = NO;
        [panel addSubview:logView];

        // COPY
        UIButton *copy = [UIButton buttonWithType:UIButtonTypeSystem];
        copy.frame = CGRectMake(10, 170, 60, 30);
        [copy setTitle:@"Copy" forState:UIControlStateNormal];
        [copy addTarget:^(id sender){
            UIPasteboard.generalPasteboard.string = logs;
            AddLog(@"Copied");
        } forControlEvents:UIControlEventTouchUpInside];
        [panel addSubview:copy];

        // CLEAR
        UIButton *clear = [UIButton buttonWithType:UIButtonTypeSystem];
        clear.frame = CGRectMake(80, 170, 60, 30);
        [clear setTitle:@"Clear" forState:UIControlStateNormal];
        [clear addTarget:^(id sender){
            [logs setString:@""];
            logView.text = @"";
        } forControlEvents:UIControlEventTouchUpInside];
        [panel addSubview:clear];

        AddLog(@"Floating log ready");

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
