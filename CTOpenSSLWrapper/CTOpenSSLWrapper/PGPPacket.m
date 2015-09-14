//
//  PGPPacket.m
//  CTOpenSSLWrapper
//
//  Created by Martin on 14.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPPacket.h"

@implementation PGPPacket

- (id)initWithBytes:(char *)bytes andWithLength: (int)length andWithTag: (int) tag andWithFormat: (int) format{
    self = [super init];
    if (self != nil) {
        self.bytes = bytes;
        self.length = length;
        self.tag = tag;
        self.format = format;
    }
    return self;
}

@end
