//
//  PGPLiteralDataPacket.h
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 25.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPPacket.h"

@interface PGPLiteralDataPacket : PGPPacket

@property (nonatomic) int formatType;
@property (nonatomic) NSString* fileName;
@property (nonatomic) unsigned int date;
@property (nonatomic) NSData* literalData;

- (id)initWithBytes:(NSData*)bytes andWithTag:(int)tag andWithFormat:(int)format;

@end
