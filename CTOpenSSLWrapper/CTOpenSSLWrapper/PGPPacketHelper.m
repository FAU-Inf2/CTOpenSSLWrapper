//
//  PGPPacketHelper.m
//  CTOpenSSLWrapper
//
//  Created by Martin on 14.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPPacketHelper.h"

@implementation PGPPacketHelper

+ (id)sharedManager {
    static PGPPacketHelper *sharedMyManager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedMyManager = [[self alloc] init];
    });
    return sharedMyManager;
}

- (id)init {
    if (self = [super init]) {
        self.packets = [[NSMutableArray alloc] init];
    }
    return self;
}

- (void) addPacketWithPGPPacket:(PGPPacket *)packet {
    [self.packets addObject:packet];
}

@end
