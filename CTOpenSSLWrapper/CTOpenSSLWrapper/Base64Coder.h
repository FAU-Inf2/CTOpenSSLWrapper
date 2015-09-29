//
//  Base64Coder.h
//  CTOpenSSLWrapper
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Base64Coder : NSObject

/*
 * Function: Decode a Base64 encoded string
 *
 * @param {NSString *} string: String to decode with Bas64
 * @return {NSData *} returns a NSData object which is Base64 decoded
 */
+ (NSData *)getDecodedBase64StringFromString:(NSString *)string;

/*
 * Function: Encode string to Base64
 *
 * @param {NSString *} string: String to encode with Bas64
 * @return {NSData *} returns a NSData object which is Base64 encoded
 */
+ (NSData *)encodeBase64String:(NSData *)data;

@end
