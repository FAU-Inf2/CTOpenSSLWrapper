//
//  Base64Coder.m
//  CTOpenSSLWrapper
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#include <openssl/bio.h>
#include <openssl/evp.h>

#import "Base64Coder.h"

@implementation Base64Coder

+ (NSString *)getDecodedBase64StringFromString:(NSString *)string {
    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:string options:0];
    return [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
}

+ (NSString *)encodeBase64String:(NSString *)string {
    NSData *plainData = [string dataUsingEncoding:NSUTF8StringEncoding];
    return [plainData base64EncodedStringWithOptions:0];
}

//+ (NSString *)encodeBase64String:(NSString *)encodedString {
//    /*
//     BIO *bio, *b64, *bio_out;
//     char inbuf[512];
//     int inlen;
//     
//     b64 = BIO_new(BIO_f_base64());
//     bio = BIO_new_fp(stdin, BIO_NOCLOSE);
//     bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
//     BIO_push(b64, bio);
//     while((inlen = BIO_read(b64, inbuf, 512)) > 0)
//     BIO_write(bio_out, inbuf, inlen);
//     
//     BIO_flush(bio_out);
//     BIO_free_all(b64);
//    */
//    BIO *bio, *b64, *bio_out;
////    char inbuf[strln([encodedString UTF8String])];
//    int inlen;
//    
//    b64 = BIO_new(BIO_f_base64());
//    bio = BIO_new_fp(stdin, BIO_NOCLOSE);
//    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
//    BIO_push(b64, bio);
////    while ((inlen = BIO_read(b64, inbuf, strln([encodedString UTF8String]))) > 0) {
////        BIO_write(bio_out, inbuf, inlen);
////    }
//    
//    BIO_flush(bio_out);
//    BIO_free_all(b64);
//}

@end
