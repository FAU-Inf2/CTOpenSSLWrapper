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

+ (unsigned char *)removeArmorFromKeyFile:(NSURL*)fileUrl;
+ (unsigned char *)removeArmorFromKeyFileString:(NSString*)fileContent;

/*
 * Function: Adding the packet to PGPPacketHelper.
 *
 * @param {char*} bytes: decoded Base64 string
 * @param {int} position: start position of the packet
 * @return {int} returns the position where the next packet starts
 *               or 0 if the last packet was extracted
 *               or -1 on error
 */
+ (int) extractPacketsFromBytes:(unsigned char*)bytes andWithPostion:(int)position;

+ (NSData*)extractPublicKeyFromPacket:(PGPPacket*) packet;

@end
