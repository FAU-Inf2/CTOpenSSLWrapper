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

#import "NSString+CTOpenSSL.h"
#import "Base64Coder.h"

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
        NSString *encodedBase64String = [PGPArmorHelper removeArmorFromString:fileContent];
        return (char *)[[Base64Coder getDecodedBase64StringFromString:encodedBase64String] UTF8String];
    } else {
        return (char *)[[Base64Coder getDecodedBase64StringFromString:fileContent] UTF8String];
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
        int startIndex = range.location;
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
    
    return [PGPArmorHelper trimmNewLinesFromString:mutableString];
}

+ (NSString*)trimmNewLinesFromString:(NSString *)stringToTrimm {
    NSCharacterSet *whiteSpaceCharacterSet = [NSCharacterSet newlineCharacterSet];
    return [stringToTrimm stringByTrimmingCharactersInSet:whiteSpaceCharacterSet];
}

+ (void)extractPacketsFromBytes:(char *)bytes {
    int pos = 0;
    int tag;
    int format = 0; //0 = old format; 1 = new format
    int packet_length_type;
    int packet_length;
    int packet_header = bytes[pos++];
    
    //Check format
    if ((packet_header & 0x40) != 0){ //RFC 4.2. Bit 6 -- New packet format if set
        format = 1;
    }
    
    //Get tag
    if (format) {
        //new format
        tag = packet_header & 0x3F; //RFC 4.2. Bits 5-0 -- packet tag
    }else {
        //old format
        tag = (packet_header & 0x3CF) >> 2; //RFC 4.2. Bits 5-2 -- packet tag
        packet_length_type = packet_header & 0x03; //RFC 4.2. Bits 1-0 -- length-type
    }
    
    //Get packet length
    if (!format) {
        //RFC 4.2.1. Old Format Packet Lengths
        switch (packet_length_type) {
            case 0:
                //RFC: The packet has a one-octet length.  The header is 2 octets long.
                packet_length = bytes[pos++];
                break;
            case 1:
                //RFC: The packet has a two-octet length.  The header is 3 octets long.
                packet_length = (bytes[pos++] << 8);
                packet_length = packet_length | bytes[pos++];
                break;
            case 2:
                //RFC: The packet has a four-octet length.  The header is 5 octets long.
                packet_length = (bytes[pos++] << 24);
                packet_length = packet_length | (bytes[pos++] << 16);
                packet_length = packet_length | (bytes[pos++] << 8);
                packet_length = packet_length | bytes[pos++];
                break;
            case 3:
                //TODO
            default:
                break;
        }
    }else {
        //RFC 4.2.2. New Format Packet Lengths
        int first_octet = bytes[pos++];
        
        if(first_octet < 192) {
            //RFC 4.2.2.1. One-Octet Lengths
            packet_length = first_octet;
        } else if (first_octet < 234) {
            //RFC 4.2.2.2. Two-Octet Lengths
            packet_length = ((first_octet - 192) << 8) + (bytes[pos++]) + 192;
        } else if (first_octet == 255) {
            //RFC 4.2.2.3. Five-Octet Lengths
            packet_length = (bytes[pos++] << 24);
            packet_length = packet_length | (bytes[pos++] << 16);
            packet_length = packet_length | (bytes[pos++] << 8);
            packet_length = packet_length | bytes[pos++];
        } else {
            //TODO
            /*RFC: When the length of the packet body is not known in advance by the issuer,
             Partial Body Length headers encode a packet of indeterminate length,
             effectively making it a stream.*/
            return;
        }
    }
    
    //Get Packet
    char packet[packet_length];
    for (int i = 0; i < packet_length; i++) {
        packet[i] = bytes[pos++];
    }
    
    if (tag == 6) { //Public-Key Packet
        [self extractPublicKeyFromBytes:packet];
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
