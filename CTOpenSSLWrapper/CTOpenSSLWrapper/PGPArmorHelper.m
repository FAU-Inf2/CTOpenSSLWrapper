//
//  PGPArmorHelper.m
//  CTOpenSSLWrapper
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPArmorHelper.h"

#define publicArmorBegin @"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
#define publicArmorEnd @"-----END PGP PUBLIC KEY BLOCK-----\n"
#define privateArmorBegin @"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
#define privateArmorEnd @"-----END PGP PRIVATE KEY BLOCK-----\n"
#define keyFileComment @"Comment"

@implementation PGPArmorHelper

+ (BOOL)isArmored:(NSString *)fileContent {
    if ([fileContent containsString:publicArmorBegin] ||
        [fileContent containsString:publicArmorEnd] ||
        [fileContent containsString:privateArmorBegin] ||
        [fileContent containsString:privateArmorEnd] ||
        [fileContent containsString:keyFileComment]) {
        return YES;
    } else {
        return NO;
    }
}

+ (char *)removeArmorFromKeyFile:(NSURL*)fileUrl {
    NSError* error;
    NSString* contentOfURL = [NSString stringWithContentsOfURL:fileUrl encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        NSLog(@"Error while reading KeyFile: %@\nUserInfo: %@", error, error.userInfo);
        return NULL;
    } else {
        return [PGPArmorHelper removeArmorFromKeyFileString:contentOfURL];
    }
}

+ (char *)removeArmorFromKeyFileString:(NSString*)fileContent {
    if ([PGPArmorHelper isArmored:fileContent]) {
        return (char *)[[PGPArmorHelper removeArmorFromString:fileContent] UTF8String];
    } else {
        return (char *)[fileContent UTF8String];
    }
}

+ (NSString*)removeArmorFromString:(NSString*)string {
    string = [string stringByReplacingOccurrencesOfString:publicArmorBegin withString:@""];
    string = [string stringByReplacingOccurrencesOfString:publicArmorEnd withString:@""];
    string = [string stringByReplacingOccurrencesOfString:privateArmorBegin withString:@""];
    string = [string stringByReplacingOccurrencesOfString:privateArmorEnd withString:@""];
    
    NSMutableString *mutableString = [string mutableCopy];
    NSRange range;
    while ((range = [mutableString rangeOfString:keyFileComment]).location != NSNotFound) {
        int startIndex = range.location + range.length;
        int endIndex = 0;
        for (int i = startIndex; startIndex < string.length; i++) {
            NSString* substring = [string substringWithRange:NSMakeRange(i, 1)];
            if([substring isEqualToString:@"\n"]) {
                endIndex = i;
                break;
            }
        }
        if (endIndex != 0) {
            [mutableString deleteCharactersInRange:NSMakeRange(startIndex, endIndex - startIndex)];
        }
    }
    
    return mutableString;
}


@end
