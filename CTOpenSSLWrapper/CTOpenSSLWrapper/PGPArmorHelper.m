//
//  PGPArmorHelper.m
//  CTOpenSSLWrapper
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPArmorHelper.h"
#include <openssl/ossl_typ.h>
#include <openssl/bn.h>

#define publicArmorBegin @"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
#define publicArmorEnd @"-----END PGP PUBLIC KEY BLOCK-----\n"
#define privateArmorBegin @"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
#define privateArmorEnd @"-----END PGP PRIVATE KEY BLOCK-----\n"
#define keyFileComment @"Comment"

@implementation PGPArmorHelper

+ (BOOL)isArmored:(NSString *)fileContent {
    if ([fileContent containsString:publicArmorBegin] ||
        [fileContent containsString:publicArmorEnd] ||
        [fileContent containsString:privateArmorBegin] ||
        [fileContent containsString:privateArmorEnd] ||
        [fileContent containsString:keyFileComment]) {
        return YES;
    } else {
        return NO;
    }
}

+ (char *)removeArmorFromKeyFile:(NSURL*)fileUrl {
    NSError* error;
    NSString* contentOfURL = [NSString stringWithContentsOfURL:fileUrl encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        NSLog(@"Error while reading KeyFile: %@\nUserInfo: %@", error, error.userInfo);
        return NULL;
    } else {
        return [PGPArmorHelper removeArmorFromKeyFileString:contentOfURL];
    }
}

+ (char *)removeArmorFromKeyFileString:(NSString*)fileContent {
    if ([PGPArmorHelper isArmored:fileContent]) {
        return (char *)[[PGPArmorHelper removeArmorFromString:fileContent] UTF8String];
    } else {
        return (char *)[fileContent UTF8String];
    }
}

+ (NSString*)removeArmorFromString:(NSString*)string {
    string = [string stringByReplacingOccurrencesOfString:publicArmorBegin withString:@""];
    string = [string stringByReplacingOccurrencesOfString:publicArmorEnd withString:@""];
    string = [string stringByReplacingOccurrencesOfString:privateArmorBegin withString:@""];
    string = [string stringByReplacingOccurrencesOfString:privateArmorEnd withString:@""];
    
    NSMutableString *mutableString = [string mutableCopy];
    NSRange range;
    while ((range = [mutableString rangeOfString:keyFileComment]).location != NSNotFound) {
        int startIndex = range.location + range.length;
        int endIndex = 0;
        for (int i = startIndex; startIndex < string.length; i++) {
            NSString* substring = [string substringWithRange:NSMakeRange(i, 1)];
            if([substring isEqualToString:@"\n"]) {
                endIndex = i;
                break;
            }
        }
        if (endIndex != 0) {
            [mutableString deleteCharactersInRange:NSMakeRange(startIndex, endIndex - startIndex)];
        }
    }
    
    return mutableString;
}

+ (void)extractPacketsFromBytes:(char *)bytes {
    int tag = bytes[0];
    int first_octet = bytes[1];
    int second_octet = bytes[2];
    int third_octet = bytes[3];
    int fourth_octet = bytes[4];
    int fiveth_octet = bytes[5];
    int bodyLen = 0;
    int offset = 0;
    
    if (tag == 0xC6) { //Tag 6 == Public Key Packet
        NSLog(@"Tag == 6");
        if (first_octet < 192) {
            bodyLen = first_octet;
            offset = 2;
            NSLog(@"bodyLen = %d, offset = %d", bodyLen, offset);
            
        }else if (first_octet < 224) {
            bodyLen = ((first_octet - 192) << 8) + (second_octet) + 192;
            offset = 3;
            NSLog(@"bodyLen = %d, offset = %d", bodyLen, offset);
            
        }else if (first_octet == 255) {
            bodyLen = (second_octet << 24) | (third_octet << 16) | (fourth_octet << 8)  | fiveth_octet;
            offset = 6;
            NSLog(@"bodyLen = %d, offset = %d", bodyLen, offset);
            
        }else {
            //Exception
            return;
        }
        
        //Fill Body
        char body[bodyLen];
        for (int i = 0; i < bodyLen; i++) {
            body[i] = bytes[i+offset];
        }
        [self extractPublicKeyFromBytes:body];
    }
}

+ (void)extractPublicKeyFromBytes:(char *)bytes {
    int pos = 0;
    char version = bytes[pos++];
    NSLog(@"PGP public key version: %d", version);
    
    if (version == 3 || version == 4) {
        //created = util.readDate(bytes.substr(pos, 4));
        pos += 4;
        
        if (version == 3) {
            //this.expirationTimeV3 = util.readNumber(bytes.substr(pos, 2));
            pos += 2;
        }
    }
    
    int algorithm = bytes[pos++];
    NSLog(@"PGP public key algorithm: %d", algorithm);
    
    char* bmpi = bytes + pos;
    int p = 0;
    
    for (int i = 0; i < 2 && p < strlen(bmpi); i++) {
        double len = (bmpi[p] << 8) | bmpi[p+1];
        int byteLen = ceil(len / 8);
        NSLog(@"MPI %d len: %d", i, byteLen);
        BIGNUM* payload = BN_new();
        char mpi[strlen(bmpi)+2];
        mpi[0] = 'a';
        mpi[1] = 'a';
        mpi[2] = '\0';
        strncat(mpi, bmpi, strlen(bmpi));
        mpi[0] = '\0';
        mpi[1] = '\0';
        BN_mpi2bn((const unsigned char*) mpi, byteLen, payload);
        NSLog(@"MPI %d value: %@", i, payload);
        p += 2+len;
    }
    
}

@end
