//
//  Base64Coder.h
//  CTOpenSSLWrapper
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Base64Coder : NSObject

+ (unsigned char *)getDecodedBase64StringFromString:(NSString *)string;

+ (unsigned char *)encodeBase64String:(NSString *)string;

@end
