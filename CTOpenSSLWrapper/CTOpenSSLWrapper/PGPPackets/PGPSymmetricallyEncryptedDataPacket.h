//
//  PGPSymmetricallyEncryptedDataPacket.h
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 07.10.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPPacket.h"

@interface PGPSymmetricallyEncryptedDataPacket : PGPPacket

@property (nonatomic) NSData* encryptedData;

- (id)initWithBytes:(NSData*)bytes andWithTag:(int)tag andWithFormat:(int)format;

@end
