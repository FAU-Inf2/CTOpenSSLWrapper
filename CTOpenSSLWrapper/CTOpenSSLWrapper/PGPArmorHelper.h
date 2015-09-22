//
//  PGPArmorHelper.h
//  CTOpenSSLWrapper
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

@interface PGPArmorHelper : NSObject

/*
 * Function: Remove armor and decode Base64 content from a fileurl
 *
 * @param {NSURL *} fileUrl: Content of fileUrl to remove armor and to decode with Base64
 * @return {NSData *} returns a NSData object which has no armor and is Base64 decoded
 */
+ (NSData *)removeArmorFromKeyFile:(NSURL*)fileUrl;

/*
 * Function: Remove armor and decode Base64 content from a string
 *
 * @param {NSString *} fileContent: String to remove armor and to decode with Base64
 * @return {NSData *} returns a NSData object which has no armor and is Base64 decoded
 */
+ (NSData *)removeArmorFromKeyFileString:(NSString*)fileContent;

@end
