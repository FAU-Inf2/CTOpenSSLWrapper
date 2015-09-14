//
//  Base64Coder.h
//  CTOpenSSLWrapper
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Base64Coder : NSObject

+ (char *)getDecodedBase64StringFromString:(NSString *)string;

+ (NSString *)encodeBase64String:(NSString *)string;

@end
