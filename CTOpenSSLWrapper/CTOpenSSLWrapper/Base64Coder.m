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
#include <stdio.h>

#import "Base64Coder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include "../apps/apps.h"
#include <openssl/buffer.h>
#include <openssl/err.h>
//#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#undef SIZE
#undef BSIZE
#undef PROG

#define SIZE    (512)
#define BSIZE   (8*1024)

int decode()
{
    unsigned char *buff = NULL, *bufsize = NULL;
    int bsize = BSIZE, verbose = 0;
    int ret = 1, inl;
    int enc = 1, printkey = 0, base64 = 0;
    int debug = 0;
    char *inf = NULL, *outf = NULL;
    BIO *in = NULL, *out = NULL, *b64 = NULL, *benc = NULL, *rbio =
    NULL, *wbio = NULL;
    BIO *bio_err = NULL;
    
    if (bio_err == NULL)
        if ((bio_err = BIO_new(BIO_s_file())) != NULL)
            BIO_set_fp(bio_err, stderr, BIO_NOCLOSE);
    
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *basePath = paths.firstObject;
    inf = (char *)[[basePath stringByAppendingPathComponent:@"encoded.txt"] UTF8String];
    outf = (char *)[[basePath stringByAppendingPathComponent:@"decoded"] UTF8String];
    enc = 0;
    verbose = 1;
    base64 = 1;
    debug = 1;
    
    
    if (bufsize != NULL) {
        int i;
        unsigned long n;
        
        for (n = 0; *bufsize; bufsize++) {
            i = *bufsize;
            if ((i <= '9') && (i >= '0'))
                n = n * 10 + i - '0';
            else if (i == 'k') {
                n *= 1024;
                bufsize++;
                break;
            }
        }
        if (*bufsize != '\0') {
            BIO_printf(bio_err, "invalid 'bufsize' specified.\n");
            goto end;
        }
        
        /* It must be large enough for a base64 encoded line */
        if (n < 80)
            n = 80;
        
        bsize = (int)n;
        if (verbose)
            BIO_printf(bio_err, "bufsize=%d\n", bsize);
    }
    
    buff = OPENSSL_malloc(EVP_ENCODE_LENGTH(bsize));
    if (buff == NULL) {
        BIO_printf(bio_err, "OPENSSL_malloc failure\n");
        goto end;
    }
    
    in = BIO_new(BIO_s_file());
    out = BIO_new(BIO_s_file());
    if ((in == NULL) || (out == NULL)) {
        ERR_print_errors(bio_err);
        goto end;
    }
    if (debug) {
        BIO_set_callback(in, BIO_debug_callback);
        BIO_set_callback(out, BIO_debug_callback);
        BIO_set_callback_arg(in, bio_err);
        BIO_set_callback_arg(out, bio_err);
    }
    
//    if (inf == NULL)
//        BIO_set_fp(in, stdin, BIO_NOCLOSE);
//        else {
            if (BIO_read_filename(in, inf) <= 0) {
                perror(inf);
                goto end;
            }
//        }
//    
//    if (outf == NULL)
//        BIO_set_fp(out, stdout, BIO_NOCLOSE);
//        else {
//            if (BIO_write_filename(out, outf) <= 0) {
//                perror(outf);
//                goto end;
//            }
//        }
    
    rbio = in;
//    wbio = out;
    
    if (base64) {
        if ((b64 = BIO_new(BIO_f_base64())) == NULL)
            goto end;
        if (debug) {
            BIO_set_callback(b64, BIO_debug_callback);
            BIO_set_callback_arg(b64, bio_err);
        }
//        if (enc)
//            wbio = BIO_push(b64, wbio);
//        else
            rbio = BIO_push(b64, rbio);
    }
    
    for (;;) {
        inl = BIO_read(rbio, (char *)buff, bsize);
        if (inl <= 0)
            break;
//        if (BIO_write(wbio, (char *)buff, inl) != inl) {
//            BIO_printf(bio_err, "error writing output file\n");
//            goto end;
//        }
    }
//    BIO_flush(wbio);
    
    ret = 0;
    if (verbose) {
        BIO_printf(bio_err, "bytes read   :%8ld\n", BIO_number_read(in));
        BIO_printf(bio_err, "bytes written:%8ld\n", BIO_number_written(out));
    }
end:
    OPENSSL_free(buff);
    BIO_free(in);
    BIO_free(out);
    BIO_free(benc);
    BIO_free(b64);
    return ret;
}

@implementation Base64Coder

//+ (char *)getDecodedBase64StringFromString:(NSString *)string {
//    
////    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:string options:0];
////    NSLog(@"%s", (char *)[decodedData bytes]);
////    return (char *)[decodedData bytes];
//}

+ (NSString *)encodeBase64String:(NSString *)string {
    NSData *plainData = [string dataUsingEncoding:NSUTF8StringEncoding];
    return [plainData base64EncodedStringWithOptions:0];
}

+ (char *)getDecodedBase64StringFromString:(NSString *)encodedString {
    
     NSMutableString* mutableString = [encodedString mutableCopy];
    NSString *docPath = [[Base64Coder applicationDocumentsDirectory] stringByAppendingPathComponent:@"encoded.txt"];
    NSError *error;
    [mutableString writeToFile:docPath atomically:NO encoding:NSUTF8StringEncoding error:&error];
    if (error != nil) {
        NSLog(@"%@", error.description);
    }
    
    decode();

    
    NSMutableString *decodedString = [NSMutableString new];
    [mutableString appendString:@"\n"];
    
    BIO *bio, *b64;
    BIO *input = NULL;
    char* buffer;//[512];
    int decodeLen = [Base64Coder calcDecodeLenthWithString:mutableString];
    buffer = OPENSSL_malloc(EVP_ENCODE_LENGTH(decodeLen + 1));
    
    
    FILE* file = fopen((char *)[docPath UTF8String], "r");
    input = BIO_new(BIO_s_file());
    BIO_read_filename(input, (char *)[docPath UTF8String]);
    
    BIO *output = BIO_new(BIO_s_file());
    BIO_set_fp(output, stdout, BIO_NOCLOSE);
    
    b64 = BIO_new(BIO_f_base64());
    BIO_set_callback(b64, BIO_debug_callback);
    BIO *bio_err = BIO_new(BIO_s_file());
    BIO_set_fp(bio_err, stderr, BIO_NOCLOSE);
    BIO_set_callback_arg(b64, (char *)bio_err);
    BIO_set_callback(input, BIO_debug_callback);
    BIO_set_callback_arg(input, (char *)bio_err);
    input = BIO_push(b64, input);
    
    (buffer)[0] = '\0';
    (buffer)[decodeLen] = '\0';
    BIO_read(input, buffer, decodeLen);
    
#ifndef NDEBUG
    BIO* bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_write(bio_out, buffer, decodeLen);
#endif
    
    while(decodeLen > 0) {
        int readLength;
        if (decodeLen > 512) {
            readLength = 512;
            decodeLen -= 512;
        } else {
            readLength = decodeLen;
            decodeLen = 0;
        }
        int len = BIO_read(b64, buffer, readLength);
        ERR_print_errors(bio_err);
        len = BIO_read(b64, buffer, readLength);
        [decodedString appendString:[NSString stringWithCharacters:buffer length:readLength]];
    }
    
    //Can test here if len == decodeLen - if not, then return an error
    
    BIO_free_all(bio);
//    fclose(stream);
    
    
    return (char *)[decodedString UTF8String];
}

+ (size_t)calcDecodeLenthWithString:(NSString *)string {
    //Calculates the length of a decoded string
    const char* b64input = (const char*)[string UTF8String];
    size_t len = strlen(b64input),
    padding = 0;
    
    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
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
