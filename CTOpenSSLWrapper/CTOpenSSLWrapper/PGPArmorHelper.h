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

/*
 * Function: Adding the packet to PGPPacketHelper.
 *
 * @param {char*} bytes: decoded Base64 string
 * @param {int} position: start position of the packet
 * @return {int} returns the position where the next packet starts
 *               or 0 if the last packet was extracted
 *               or -1 on error
 */
+ (int)extractPacketsFromBytes:(unsigned char*)bytes withLength:(int)length andWithPostion:(int)position;

+ (NSData*)extractPrivateKeyFromPacket:(PGPPacket*) packet;
+ (NSData*)extractPublicKeyFromPacket:(PGPPacket*) packet pos:(int*) position;
+ (NSData*)extractEncryptedSymmetricSessionKeyFromPacket:(PGPPacket*) packet;

@end
