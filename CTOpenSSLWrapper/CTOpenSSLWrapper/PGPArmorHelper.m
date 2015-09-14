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
#import "PGPPacketHelper.h"

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

+ (int)extractPacketsFromBytes:(char *)bytes andWithPostion:(int)position {
    int pos = position;
    int packet_tag = -1;
    int packet_format = 0; //0 = old format; 1 = new format
    int packet_length_type = -1;
    size_t packet_length = -1;
    int packet_header = (Byte) bytes[pos++];
    
    //Check format
    if ((packet_header & 0x40) != 0){ //RFC 4.2. Bit 6 -- New packet format if set
        packet_format = 1;
    }
    
    //Get tag
    if (packet_format) {
        //new format
        packet_tag = packet_header & 0x3F; //RFC 4.2. Bits 5-0 -- packet tag
    }else {
        //old format
        packet_tag = (packet_header & 0x3C) >> 2; //RFC 4.2. Bits 5-2 -- packet tag
        packet_length_type = packet_header & 0x03; //RFC 4.2. Bits 1-0 -- length-type
    }
    
    //Get packet length
    if (!packet_format) {
        //RFC 4.2.1. Old Format Packet Lengths
        switch (packet_length_type) {
            case 0:
                //RFC: The packet has a one-octet length.  The header is 2 octets long.
                packet_length = (Byte) bytes[pos++];
                break;
            case 1:
                //RFC: The packet has a two-octet length.  The header is 3 octets long.
                packet_length = ((Byte) bytes[pos++] << 8);
                packet_length = packet_length | (Byte) bytes[pos++];
                break;
            case 2:
                //RFC: The packet has a four-octet length.  The header is 5 octets long.
                packet_length = ((Byte) bytes[pos++] << 24);
                packet_length = packet_length | ((Byte) bytes[pos++] << 16);
                packet_length = packet_length | ((Byte) bytes[pos++] << 8);
                packet_length = packet_length | (Byte) bytes[pos++];
                break;
            case 3:
                //TODO
                return -1;
                break;
            default:
                return -1;
                break;
        }
    }else {
        //RFC 4.2.2. New Format Packet Lengths
        int first_octet = (Byte) bytes[pos++];
        
        if(first_octet < 192) {
            //RFC 4.2.2.1. One-Octet Lengths
            packet_length = first_octet;
        } else if (first_octet < 234) {
            //RFC 4.2.2.2. Two-Octet Lengths
            packet_length = ((first_octet - 192) << 8) + ((Byte) bytes[pos++]) + 192;
        } else if (first_octet == 255) {
            //RFC 4.2.2.3. Five-Octet Lengths
            packet_length = ((Byte) bytes[pos++] << 24);
            packet_length = packet_length | ((Byte) bytes[pos++] << 16);
            packet_length = packet_length | ((Byte) bytes[pos++] << 8);
            packet_length = packet_length | (Byte) bytes[pos++];
        } else {
            //TODO
            /*RFC: When the length of the packet body is not known in advance by the issuer,
             Partial Body Length headers encode a packet of indeterminate length,
             effectively making it a stream.*/
            return -1;
        }
    }
    
    //Get Packet_bytes
    //TODO: move allocation of memory to [PGPPacket initWithBytes]
    char* packet_bytes = calloc(packet_length, sizeof(char));
    for (int i = 0; i < packet_length; i++) {
        packet_bytes[i] = bytes[i+pos];
    }

    PGPPacket *packet = [[PGPPacket alloc] initWithBytes:packet_bytes andWithLength:packet_length andWithTag:packet_tag andWithFormat:packet_format];
    
    [[PGPPacketHelper sharedManager] addPacketWithPGPPacket:packet];
    
    if (strlen(bytes) == position+packet_length+1){
        return 0; //End of bytes
    }
    
    return pos;
}

+ (NSData*)extractPublicKeyFromPacket:(PGPPacket*) packet {
    int pos = 0;
    int version = (Byte) packet.bytes[pos++];
    NSLog(@"PGP public key version: %d", version);
    
    if (version == 3 || version == 4) {
        //created = util.readDate(bytes.substr(pos, 4));
        pos += 4;
        
        if (version == 3) {
            //this.expirationTimeV3 = util.readNumber(bytes.substr(pos, 2));
            pos += 2;
        }
    }
    
    int algorithm = (Byte) packet.bytes[pos++];
    NSLog(@"PGP public key algorithm: %d", algorithm);
    
    char* bmpi = packet.bytes + pos;
    int p = 0;
    
    /*for (int i = 0; i < 2 && p < packet.length - pos; i++) {
        double len = (bmpi[p] << 8) | bmpi[p+1];
        size_t byteLen = ceil(len / 8);
        NSLog(@"MPI %d len: %zu", i, byteLen);
        BIGNUM* payload = BN_new();
        char mpi[byteLen+4];
        mpi[0] = '\0';
        mpi[1] = '\0';
        for (int j = 0; j < byteLen+2; j++) {
            mpi[j+2] = bmpi[p+j];
        }
        BN_mpi2bn((const unsigned char*) mpi, byteLen, payload);
        //NSLog(@"MPI %d value: %@", i, payload);
        p += 2+byteLen;
    }*/
    
    double len = (bmpi[p] << 8) | bmpi[p+1];
    int byteLen = ceil(len / 8);
    
    char rsaKey[byteLen];
    
    for (int i = 0; i < byteLen; i++) {
        rsaKey[i] = bmpi[i+2];
    }
    
    NSString* string = [[NSString alloc] initWithCString:rsaKey encoding:NSUnicodeStringEncoding];
    
    return [[NSData alloc] initWithBase64EncodedString:[Base64Coder encodeBase64String:string] options:0];
    
}

@end
