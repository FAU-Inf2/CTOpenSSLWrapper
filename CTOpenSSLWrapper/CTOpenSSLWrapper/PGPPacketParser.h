//
//  PGPPacketHelper.h
//  CTOpenSSLWrapper
//
//  Created by Martin on 14.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

#import "PGPPublicKeyEncryptedSessionKeyPacket.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSymmetricEncryptedIntegrityProtectedDataPacket.h"
#import "PGPCompressedDataPacket.h"
#import "PGPLiteralDataPacket.h"
#import "PGPUserIDPacket.h"
#import "PGPSymmetricallyEncryptedDataPacket.h"

@interface PGPPacketParser : NSObject

@property (nonatomic, strong) NSArray *packets;

- (void) addPacketWithTag:(int)tag andFormat:(int)format andData:(NSData*)data;
- (NSMutableArray*)getPacketsWithTag:(int) tag;

- (int)extractPacketsFromBytes:(NSData*)bytes atPostion:(int)position;
- (int)parseSecretKeyPacket:(PGPSecretKeyPacket*) packet;
- (int)parsePublicKeyPacket:(PGPPublicKeyPacket*) packet;
- (int)parsePublicKeyEncryptedSessionKeyPacket:(PGPPublicKeyEncryptedSessionKeyPacket*) packet;
- (int)parseSymmetricEncryptedIntegrityProtectedDataPacket:(PGPSymmetricEncryptedIntegrityProtectedDataPacket*) packet;
- (int)parseCompressedDataPacket:(PGPCompressedDataPacket*) packet;
- (int)parseLiteralDataPacket:(PGPLiteralDataPacket*) packet;
- (int)parseUserIDPacket:(PGPUserIDPacket*) packet;
- (int)parseSymmetricallyEncryptedDataPacket:(PGPSymmetricallyEncryptedDataPacket*) packet;
- (NSData*)getPEMFromSecretKeyPacket:(PGPSecretKeyPacket*) packet;
- (NSData*)getPEMFromPublicKeyPacket:(PGPPublicKeyPacket*) packet;
- (NSData*)generateKeyID:(PGPPublicKeyPacket*) packet;

@end
