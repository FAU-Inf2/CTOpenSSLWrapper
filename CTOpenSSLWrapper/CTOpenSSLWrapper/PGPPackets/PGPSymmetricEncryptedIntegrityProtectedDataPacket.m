//
//  PGPSymmetricEncryptedIntegrityProtectedDataPacket.m
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 22.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPSymmetricEncryptedIntegrityProtectedDataPacket.h"

@implementation PGPSymmetricEncryptedIntegrityProtectedDataPacket

- (id)initWithBytes:(NSData*)bytes andWithTag:(int)tag andWithFormat:(int)format {
    return self = [super initWithBytes:bytes andWithTag:tag andWithFormat:format];
}

@end
