//
//  PGPArmorHelper.m
//  CTOpenSSLWrapper
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPArmorHelper.h"

#import "NSString+CTOpenSSL.h"
#import "Base64Coder.h"

#define publicArmorBegin @"-----BEGIN PGP PUBLIC KEY BLOCK-----"
#define publicArmorEnd @"-----END PGP PUBLIC KEY BLOCK-----"
#define privateArmorBegin @"-----BEGIN PGP PRIVATE KEY BLOCK-----"
#define privateArmorEnd @"-----END PGP PRIVATE KEY BLOCK-----"
#define pgpMessageBegin @"-----BEGIN PGP MESSAGE-----"
#define pgpMessageEnd @"-----END PGP MESSAGE-----"
#define keyFileComment @"Comment"
#define keyFileVersion @"Version"

@implementation PGPArmorHelper

+ (BOOL)isArmored:(NSString *)fileContent {
    if ([fileContent containsString:publicArmorBegin] ||
        [fileContent containsString:publicArmorEnd] ||
        [fileContent containsString:privateArmorBegin] ||
        [fileContent containsString:privateArmorEnd] ||
        [fileContent containsString:keyFileComment] ||
        [fileContent containsString:pgpMessageBegin] ||
        [fileContent containsString:pgpMessageEnd]) {
        return YES;
    } else {
        return NO;
    }
}

+ (NSData *)removeArmorFromKeyFile:(NSURL*)fileUrl {
    NSError* error;
    NSString* contentOfURL = [NSString stringWithContentsOfURL:fileUrl encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        NSLog(@"Error while reading KeyFile: %@\nUserInfo: %@", error, error.userInfo);
        return NULL;
    } else {
        return [PGPArmorHelper removeArmorFromKeyFileString:contentOfURL];
    }
}

+ (NSData *)removeArmorFromKeyFileString:(NSString*)fileContent {
    if ([PGPArmorHelper isArmored:fileContent]) {
        NSString *encodedBase64String = [PGPArmorHelper removeArmorFromString:fileContent];
        return [Base64Coder getDecodedBase64StringFromString:encodedBase64String];
    } else {
        return [NSData dataWithBytes:[fileContent UTF8String] length:fileContent.length];
    }
}

+ (NSString*)removeArmorFromString:(NSString*)string {
    string = [string stringByReplacingOccurrencesOfString:publicArmorBegin withString:@""];
    string = [string stringByReplacingOccurrencesOfString:publicArmorEnd withString:@""];
    string = [string stringByReplacingOccurrencesOfString:privateArmorBegin withString:@""];
    string = [string stringByReplacingOccurrencesOfString:privateArmorEnd withString:@""];
    string = [string stringByReplacingOccurrencesOfString:pgpMessageBegin withString:@""];
    string = [string stringByReplacingOccurrencesOfString:pgpMessageEnd withString:@""];
    
    NSMutableString *mutableString = [string mutableCopy];
    NSRange range;
    while ((range = [mutableString rangeOfString:keyFileComment]).location != NSNotFound) {
        NSUInteger startIndex = range.location;
        NSUInteger endIndex = 0;
        for (NSUInteger i = startIndex; startIndex < string.length; i++) {
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
    
    while ((range = [mutableString rangeOfString:keyFileVersion]).location != NSNotFound) {
        NSUInteger startIndex = range.location;
        NSUInteger endIndex = 0;
        for (NSUInteger i = startIndex; startIndex < string.length; i++) {
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
    
    //Remove newlines
    mutableString = [[PGPArmorHelper trimmNewLinesFromString:mutableString] mutableCopy];
    
    //Remove checksum from base64 string
    mutableString = [[mutableString substringToIndex:mutableString.length - 6] mutableCopy];
    
    return mutableString;
}

+ (NSString*)trimmNewLinesFromString:(NSString *)stringToTrimm {
    NSCharacterSet *whiteSpaceCharacterSet = [NSCharacterSet whitespaceAndNewlineCharacterSet];
    return [stringToTrimm stringByTrimmingCharactersInSet:whiteSpaceCharacterSet];
}

@end
