//
//  Base64Coder.m
//  CTOpenSSLWrapper
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>

#import "Base64Coder.h"

@implementation Base64Coder

+ (unsigned char *)encodeBase64String:(NSString *)string {

    BIO *bio, *b64;
    BIO *bio_err = BIO_new(BIO_s_file());
    char *message = (char *)[string UTF8String];
    
    NSString *docPath = [[Base64Coder applicationDocumentsDirectory] stringByAppendingPathComponent:@"stringToEncode.txt"];
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_file());
    BIO_write_filename(bio, (char *)[docPath UTF8String]);
#ifndef NDebug
    BIO_set_callback(bio, BIO_debug_callback);
    BIO_set_callback_arg(bio, (char *)bio_err);
    BIO_set_callback(b64, BIO_debug_callback);
    BIO_set_callback_arg(b64, (char *)bio_err);
#endif
    BIO_push(b64, bio);
    BIO_write(b64, message, strlen(message));
    BIO_flush(b64);
    
    BIO_free_all(bio);
    
    NSData *encodedData = [NSData dataWithContentsOfFile:docPath];
    
    NSError *error;
    [[NSFileManager defaultManager] removeItemAtPath:docPath error:&error];
    if (error != nil) {
        NSLog(@"%@", error.description);
    }
    
    return (unsigned char *)encodedData.bytes;
    
}

+ (unsigned char *)getDecodedBase64StringFromString:(NSString *)encodedString {
    
    BIO *b64;
    BIO *input = NULL;
    BIO *bio_err = BIO_new(BIO_s_file());
    BIO_set_fp(bio_err, stderr, BIO_NOCLOSE);
    unsigned char* buffer;
    int decodeLen = [Base64Coder calcDecodeLenthWithString:encodedString];
    buffer = OPENSSL_malloc(EVP_ENCODE_LENGTH(decodeLen + 1));
    
    NSString *docPath = [[Base64Coder applicationDocumentsDirectory] stringByAppendingPathComponent:@"encoded.txt"];
    NSError *error;
    [encodedString writeToFile:docPath atomically:NO encoding:NSUTF8StringEncoding error:&error];
    if (error != nil) {
        NSLog(@"%@", error.description);
    }
    
    input = BIO_new(BIO_s_file());
    BIO_read_filename(input, (char *)[docPath UTF8String]);
    
    b64 = BIO_new(BIO_f_base64());
#ifndef NDEBUG
    BIO_set_callback(b64, BIO_debug_callback);
    BIO_set_callback_arg(b64, (char *)bio_err);
    BIO_set_callback(input, BIO_debug_callback);
    BIO_set_callback_arg(input, (char *)bio_err);
#endif
    input = BIO_push(b64, input);
    
    (buffer)[decodeLen] = '\0';
    BIO_read(input, buffer, decodeLen);
    
#ifndef NDEBUG
    BIO* bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_write(bio_out, buffer, decodeLen);
#endif
    
    BIO_free_all(input);
    BIO_free_all(bio_err);
    
    error = nil;
    [[NSFileManager defaultManager] removeItemAtPath:docPath error:&error];
    if (error != nil) {
        NSLog(@"%@", error.description);
    }
    
    return buffer;
}

+ (size_t)calcDecodeLenthWithString:(NSString *)string {
    const char* b64input = (const char*)[string UTF8String];
    size_t len = strlen(b64input),
    padding = 0;
    
    if (b64input[len-1] == '=' && b64input[len-2] == '=')
        padding = 2;
    else if (b64input[len-1] == '=')
        padding = 1;
    
    return (len*3)/4 - padding;
}

+ (NSString *) applicationDocumentsDirectory
{
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *basePath = paths.firstObject;
    return basePath;
}

@end
