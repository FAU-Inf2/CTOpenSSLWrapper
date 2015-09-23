//
//  SecretKeyPacket.h
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 22.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//
#import "PGPPacket.h"
#import "PGPPublicKeyPacket.h"

@interface PGPSecretKeyPacket : PGPPacket

@property (nonatomic) PGPPublicKeyPacket *pubKey;
@property (nonatomic) int s2k;
@property (nonatomic) NSMutableArray *mpis;

- (id)initWithBytes:(NSData*)bytes andWithTag:(int)tag andWithFormat:(int)format;

@end
