//
//  PGPSymmetricEncryptedIntegrityProtectedDataPacket.h
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 22.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPPacket.h"

@interface PGPSymmetricEncryptedIntegrityProtectedDataPacket : PGPPacket

@property (nonatomic) int version;
@property (nonatomic) NSData *encryptedData;

- (id)initWithBytes:(NSData*)bytes andWithTag:(int)tag andWithFormat:(int)format;
- (NSData*)checkPacketFromDecryptedData:(NSData*)decryptedData;

@end
