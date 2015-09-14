//
//  PGPPacket.h
//  CTOpenSSLWrapper
//
//  Created by Martin on 14.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPPacket : NSObject

@property (nonatomic) char* bytes;
@property (nonatomic) int length;
@property (nonatomic) int tag;
@property (nonatomic) int format;

- (id)initWithBytes:(char *)bytes andWithLength: (int)length andWithTag: (int) tag andWithFormat: (int) format;

@end
