//
//  PGPArmorHelper.m
//  CTOpenSSLWrapper
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPArmorHelper.h"
#import <openssl/ossl_typ.h>
#import <openssl/bn.h>
#import <openssl/rsa.h>
#import <openssl/pem.h>

#import "NSString+CTOpenSSL.h"
#import "Base64Coder.h"
#import "PGPPacketHelper.h"

#define publicArmorBegin @"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
#define publicArmorEnd @"-----END PGP PUBLIC KEY BLOCK-----\n"
#define privateArmorBegin @"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
#define privateArmorEnd @"-----END PGP PRIVATE KEY BLOCK-----\n"
#define keyFileComment @"Comment"

static BIGNUM *mpi2bn(const unsigned char *d, int n, BIGNUM *a)
{
    long len;
    int neg = 0;
    
    if (n < 4) {
        //BNerr(BN_F_BN_MPI2BN, BN_R_INVALID_LENGTH);
        return (NULL);
    }
    len = ((long)d[0] << 24) | ((long)d[1] << 16) | ((int)d[2] << 8) | (int)
    d[3];
    double tmp = len;
    tmp = tmp / 8;
    len = ceil(tmp);
    
    if ((len + 4) != n) {
        //BNerr(BN_F_BN_MPI2BN, BN_R_ENCODING_ERROR);
        return (NULL);
    }
    
    if (a == NULL)
        a = BN_new();
    if (a == NULL)
        return (NULL);
    
    if (len == 0) {
        a->neg = 0;
        a->top = 0;
        return (a);
    }
    d += 4;
    if ((*d) & 0x80)
        neg = 1;
    if (BN_bin2bn(d, (int)len, a) == NULL)
        return (NULL);
    a->neg = neg;
    if (neg) {
        BN_clear_bit(a, BN_num_bits(a) - 1);
    }
    bn_check_top(a);
    return (a);
}

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

+ (unsigned char *)removeArmorFromKeyFile:(NSURL*)fileUrl {
    NSError* error;
    NSString* contentOfURL = [NSString stringWithContentsOfURL:fileUrl encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        NSLog(@"Error while reading KeyFile: %@\nUserInfo: %@", error, error.userInfo);
        return NULL;
    } else {
        return [PGPArmorHelper removeArmorFromKeyFileString:contentOfURL];
    }
}

+ (unsigned char *)removeArmorFromKeyFileString:(NSString*)fileContent {
    if ([PGPArmorHelper isArmored:fileContent]) {
        NSString *encodedBase64String = [PGPArmorHelper removeArmorFromString:fileContent];
        return [Base64Coder getDecodedBase64StringFromString:encodedBase64String];
    } else {
        return (unsigned char *)[fileContent UTF8String];
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
        NSUInteger startIndex = range.location;
        NSUInteger endIndex = 0;
        for (NSUInteger i = startIndex; startIndex < string.length; i++) {
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
    
    //Remove checksum from base64 string
    mutableString = [[mutableString substringToIndex:mutableString.length - 5] mutableCopy];
    
    return [PGPArmorHelper trimmNewLinesFromString:mutableString];
}

+ (NSString*)trimmNewLinesFromString:(NSString *)stringToTrimm {
    NSCharacterSet *whiteSpaceCharacterSet = [NSCharacterSet whitespaceAndNewlineCharacterSet];
    return [stringToTrimm stringByTrimmingCharactersInSet:whiteSpaceCharacterSet];
    return [stringToTrimm substringFromIndex:2];
}

+ (int)extractPacketsFromBytes:(unsigned char *)bytes withLength:(int)length andWithPostion:(int)position {
    int pos = position;
    int packet_tag = -1;
    int packet_format = 0; //0 = old format; 1 = new format
    int packet_length_type = -1;
    size_t packet_length = -1;
    int packet_header = bytes[pos++];
    
    if ((packet_header & 0x80) == 0) {
        return -1;
    }
    
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
                packet_length =  bytes[pos++];
                break;
            case 1:
                //RFC: The packet has a two-octet length.  The header is 3 octets long.
                packet_length = ( bytes[pos++] << 8);
                packet_length = packet_length |  bytes[pos++];
                break;
            case 2:
                //RFC: The packet has a four-octet length.  The header is 5 octets long.
                packet_length = ( bytes[pos++] << 24);
                packet_length = packet_length | ( bytes[pos++] << 16);
                packet_length = packet_length | ( bytes[pos++] << 8);
                packet_length = packet_length |  bytes[pos++];
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
        int first_octet =  bytes[pos++];
        
        if(first_octet < 192) {
            //RFC 4.2.2.1. One-Octet Lengths
            packet_length = first_octet;
        } else if (first_octet < 234) {
            //RFC 4.2.2.2. Two-Octet Lengths
            packet_length = ((first_octet - 192) << 8) + ( bytes[pos++]) + 192;
        } else if (first_octet == 255) {
            //RFC 4.2.2.3. Five-Octet Lengths
            packet_length = ( bytes[pos++] << 24);
            packet_length = packet_length | ( bytes[pos++] << 16);
            packet_length = packet_length | ( bytes[pos++] << 8);
            packet_length = packet_length |  bytes[pos++];
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
    
    if (packet.tag != NULL) {
        [[PGPPacketHelper sharedManager] addPacketWithPGPPacket:packet];
    }
    
    if (length <= pos+packet_length+1){
        return 0; //End of bytes
    }
    
    return pos+packet_length;
}

+ (NSData*)extractPublicKeyFromPacket:(PGPPacket*) packet {
    int pos = 0;
    int version =  packet.bytes[pos++];
    NSLog(@"PGP public key version: %d", version);
    
    if (version == 3 || version == 4) {
        //created = util.readDate(bytes.substr(pos, 4));
        pos += 4;
        
        if (version == 3) {
            //this.expirationTimeV3 = util.readNumber(bytes.substr(pos, 2));
            pos += 2;
        }
    }
    
    int algorithm =  packet.bytes[pos++];
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
    
    // get key data
    double key_len = (bmpi[p] << 8) | bmpi[p+1];
    int key_byteLen = ceil(key_len / 8);
    
    unsigned char rsaKey[key_byteLen+4];
    
    rsaKey[0] = rsaKey[1] = '\0';
    for (int i = 0; i < key_byteLen+2; i++) {
        rsaKey[i+2] = bmpi[i];
    }
    
    p = 2+key_byteLen;
    
    /*NSMutableString *rsaString = [NSMutableString new];
    for (int i = 0; i < byteLen; i++) {
        [rsaString appendFormat:@"%c", rsaKey[i]];
    }*/
    
    // get public exponent
    double exp_len = (bmpi[p] << 8) | bmpi[p+1];
    int exp_byteLen = ceil(exp_len / 8);
    
    unsigned char pub_exp[exp_byteLen+4];
    
    pub_exp[0] = pub_exp[1] = '\0';
    for (int i = 0; i < exp_byteLen+2; i++) {
        pub_exp[i+2] = bmpi[p+i];
    }
    
    BIGNUM *keyData, *exponentData;
    keyData = mpi2bn(rsaKey, key_byteLen+4, NULL);
    if (keyData->neg) {
        BN_set_bit(keyData, ((int) key_len) - 1);
        keyData->neg = 0;
    }
    exponentData = mpi2bn(pub_exp, exp_byteLen+4, NULL);
    if (exponentData->neg) {
        BN_set_bit(exponentData, ((int) exp_len) - 1);
        exponentData->neg = 0;
    }
    
    RSA* pubKey = RSA_new();
    pubKey->n = keyData;
    pubKey->e = exponentData;
    pubKey->d = NULL;
    pubKey->p = NULL;
    pubKey->q = NULL;
    pubKey->dmp1 = NULL;
    pubKey->dmq1 = NULL;
    pubKey->iqmp = NULL;
    
    BIO *bio = BIO_new(BIO_s_mem());
    
    //PEM_write_bio_RSAPrivateKey(bio, pubKey, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSA_PUBKEY(bio, pubKey);
    
    char *bioData = NULL;
    long bioDataLength = BIO_get_mem_data(bio, &bioData);
    NSData *result = [NSData dataWithBytes:bioData length:bioDataLength];
    NSLog(@"%@", [[NSString alloc] initWithData:result encoding:NSUnicodeStringEncoding]);
    BN_free(keyData);
    BN_free(exponentData);
    //RSA_free(pubKey);
    BIO_free(bio);
    
    return result;
}

@end
