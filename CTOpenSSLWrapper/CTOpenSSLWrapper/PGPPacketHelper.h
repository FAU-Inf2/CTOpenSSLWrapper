//
//  PGPPacketHelper.h
//  CTOpenSSLWrapper
//
//  Created by Martin on 14.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

@interface PGPPacketHelper : NSObject

@property (nonatomic, strong) NSMutableArray *packets;

+ (id)sharedManager;
- (void) addPacketWithPGPPacket: (PGPPacket*)packet;

@end
