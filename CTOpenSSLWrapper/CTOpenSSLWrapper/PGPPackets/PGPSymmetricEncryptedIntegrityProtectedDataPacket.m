//
//  PGPSymmetricEncryptedIntegrityProtectedDataPacket.m
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 22.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#define MDC_LENGTH 22

#import "PGPSymmetricEncryptedIntegrityProtectedDataPacket.h"

#import "CTOpenSSLDigest.h"

@implementation PGPSymmetricEncryptedIntegrityProtectedDataPacket

- (id)initWithBytes:(NSData*)bytes andWithTag:(int)tag andWithFormat:(int)format {
    return self = [super initWithBytes:bytes andWithTag:tag andWithFormat:format];
}

- (NSData*)checkPacketFromDecryptedData:(NSData *)decryptedData {
    int check1, check2 = 0;
    unsigned char* bytes = (unsigned char*)[decryptedData bytes];
    
    check1 = bytes[14] << 8 | bytes[15];
    check2 = bytes[16] << 8 | bytes[17];
    if (check1 != check2) {
        return NULL;
    }
    
    unsigned char* mdc = bytes+([decryptedData length]-MDC_LENGTH);
    // TODO: check mdc
    NSData* dataToCheck = [NSData dataWithBytes:(const void *)bytes length:[decryptedData length]-20];//[NSData dataWithBytes:bytes length:[decryptedData length]-MDC_LENGTH];
    unsigned char* hashSum = (unsigned char*)[CTOpenSSLGenerateDigestFromData(dataToCheck, CTOpenSSLDigestTypeSHA1) bytes];
    if (*(mdc++) != 0xd3) {
        return NULL;
    }
    if (*(mdc++) != 0x14) {
        return NULL;
    }
    for (int i = 0; i < MDC_LENGTH; i++) {
        if (mdc[i] != hashSum[i]) {
            return NULL;
        }
    }
    
    return [NSData dataWithBytes:(const void *)bytes+18 length:[decryptedData length]-(18+MDC_LENGTH)];
}

@end
