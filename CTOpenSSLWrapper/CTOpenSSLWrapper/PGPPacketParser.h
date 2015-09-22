//
//  PGPPacketHelper.h
//  CTOpenSSLWrapper
//
//  Created by Martin on 14.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

@interface PGPPacketParser : NSObject

@property (nonatomic, strong) NSArray *packets;

+ (id)sharedManager;
- (void) addPacketWithTag:(int)tag andFormat:(int)format andData:(NSData*)data;

+ (int)extractPacketsFromBytes:(NSData*)bytes atPostion:(int)position;
+ (int)parseSecretKeyPacket:(PGPPacket*) packet;
+ (int)parsePublicKeyPacket:(PGPPacket*) packet;
+ (int)parsePublicKeyEncryptedSessionKeyPacket:(PGPPacket*) packet;
+ (int)parseSymmetricEncryptedIntegrityProtectedDataPacket: (PGPPacket*) packet;

@end
