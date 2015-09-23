//
//  SecretKeyPacket.h
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 22.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPPacket.h"

@interface PGPPublicKeyPacket : PGPPacket

@property (nonatomic) int version;
@property (nonatomic) unsigned int creationTime;
@property (nonatomic) int daysTillExpiration;
@property (nonatomic) int algorithm;
@property (nonatomic) NSMutableArray *mpis;

- (id)initWithBytes:(NSData*)bytes andWithTag:(int)tag andWithFormat:(int)format;

@end
