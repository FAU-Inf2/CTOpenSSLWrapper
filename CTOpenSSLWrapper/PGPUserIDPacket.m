//
//  PGPUserIDPacket.m
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 05.10.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPUserIDPacket.h"

@implementation PGPUserIDPacket

- (id)initWithBytes:(NSData*)bytes andWithTag:(int)tag andWithFormat:(int)format {
    return self = [super initWithBytes:bytes andWithTag:tag andWithFormat:format];
}

@end
