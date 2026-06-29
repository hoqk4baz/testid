//
//  DeviceIdHook.m — Sadece UIDevice swizzle, fishhook yok
//  Crash izolasyonu için minimal test versiyonu
//
//  Build:
//  clang -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//    -miphoneos-version-min=13.0 -shared -fobjc-arc -O2 \
//    -framework UIKit -framework Foundation \
//    DeviceIdHook.m -o DeviceIdHook.dylib
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

static NSString *const kFakeIdfv  = @"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";
static NSString *const kFakeName  = @"iPhone";
static NSString *const kFakeModel = @"iPhone15,2";

static IMP orig_idfv, orig_name, orig_model;

static NSUUID *h_idfv(id self, SEL _cmd) {
    return [[NSUUID alloc] initWithUUIDString:kFakeIdfv];
}
static NSString *h_name(id self, SEL _cmd)  { return kFakeName; }
static NSString *h_model(id self, SEL _cmd) { return kFakeModel; }

@interface DHInstaller : NSObject
@end
@implementation DHInstaller
+ (void)load {
    Class dev = [UIDevice class];
    Method m;
    m = class_getInstanceMethod(dev, @selector(identifierForVendor));
    if (m) { orig_idfv  = method_getImplementation(m); method_setImplementation(m, (IMP)h_idfv); }
    m = class_getInstanceMethod(dev, @selector(name));
    if (m) { orig_name  = method_getImplementation(m); method_setImplementation(m, (IMP)h_name); }
    m = class_getInstanceMethod(dev, @selector(model));
    if (m) { orig_model = method_getImplementation(m); method_setImplementation(m, (IMP)h_model); }
    NSLog(@"[DHook] UIDevice hook'ları kuruldu");
}
@end
