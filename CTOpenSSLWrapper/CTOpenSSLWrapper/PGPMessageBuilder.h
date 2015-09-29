//
//  PGPMessageBuilder.h
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 25.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "PGPPublicKeyEncryptedSessionKeyPacket.h"
#import "PGPSymmetricEncryptedIntegrityProtectedDataPacket.h"
#import "PGPCompressedDataPacket.h"
#import "PGPLiteralDataPacket.h"

@interface PGPMessageBuilder : NSObject

- (NSData*)buildPGPEncryptedMessageFromData:(NSData*)dataToEncrypt withPGPPublicKey:(NSData*)pubKey andPubKeyID:(unsigned char*)pubKeyID;
- (NSData*)getChecksumForPGPMessageData:(NSData*)pgpmessage;
- (NSData*)buildArmouredPGPMessageFromMessageData:(NSData*)messageData andChecksum:(NSData*)checksum;

- (PGPLiteralDataPacket*)buildLiteralDataPacketFromData:(NSData*) dataToEncrypt;
- (PGPCompressedDataPacket*)buildCompressedDataPacketFromData:(NSData*)dataToCompress;
- (PGPSymmetricEncryptedIntegrityProtectedDataPacket*)buildSymmetricEncryptedIntegrityProtectedDataPacketWithBytes:(NSData*)dataToEncrypt andSessionKey:(NSData*)sessionKey;
- (PGPPublicKeyEncryptedSessionKeyPacket*)buildPublicKeyEncryptedSessionKeyPacketWithPGPPublicKey:(NSData*)pubKey andSessionKey:(NSData*)sessionKey andPubKeyID:(unsigned char*)pubKeyID;
- (NSData*)getbytesFromPacket:(PGPPacket*)packet;

@end
