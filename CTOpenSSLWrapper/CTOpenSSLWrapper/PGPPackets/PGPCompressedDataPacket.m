//
//  PGPCompressedDataPacket.m
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 24.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPCompressedDataPacket.h"

@implementation PGPCompressedDataPacket

- (id)initWithBytes:(NSData*)bytes andWithTag:(int)tag andWithFormat:(int)format {
    return self = [super initWithBytes:bytes andWithTag:tag andWithFormat:format];
}

@end
