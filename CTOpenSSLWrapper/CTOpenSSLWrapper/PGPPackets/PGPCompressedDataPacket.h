//
//  PGPCompressedDataPacket.h
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 24.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPPacket.h"

@interface PGPCompressedDataPacket : PGPPacket

@property (nonatomic) int algorithm;
@property (nonatomic) NSData* compressedData;

- (id)initWithBytes:(NSData*)bytes andWithTag:(int)tag andWithFormat:(int)format;

@end
