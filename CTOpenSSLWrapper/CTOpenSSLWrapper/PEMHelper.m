//
//  PEMHelper.m
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 17.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PEMHelper.h"

#import <openssl/bn.h>
#import <openssl/rsa.h>
#import <openssl/pem.h>

@implementation PEMHelper

+ (NSData *)writeKeyToPEMWithRSA:(RSA *)rsa andIsPrivate:(BOOL) isPrivate {
    BIO *bio = BIO_new(BIO_s_mem());
    
    if (isPrivate) {
        PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    } else {
        PEM_write_bio_RSA_PUBKEY(bio, rsa);
    }
    
    char *bioData = NULL;
    long bioDataLength = BIO_get_mem_data(bio, &bioData);
    NSData *result = [NSData dataWithBytes:bioData length:bioDataLength];
    BIO_free(bio);
    
    return result;
}

+ (RSA *)readPUBKEYFromPEMdata:(NSData *)data {
    BIO *bio = BIO_new_mem_buf((unsigned char*)data.bytes, (int)data.length);
    RSA *result = NULL; // Caller needs to free this!
    
    //BIO_read(bio, (char*)data.bytes, data.length);
    PEM_read_bio_RSA_PUBKEY(bio, &result, NULL, NULL);
    
    BIO_free(bio);
    return result;
}

@end
