//
//  PGPUserIDPacket.h
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 05.10.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPPacket.h"

@interface PGPUserIDPacket : PGPPacket

@property (nonatomic) NSString* userID;

- (id)initWithBytes:(NSData*)bytes andWithTag:(int)tag andWithFormat:(int)format;

@end
