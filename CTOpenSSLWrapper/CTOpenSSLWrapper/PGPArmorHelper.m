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
#import <openssl/err.h>

#import "NSString+CTOpenSSL.h"
#import "Base64Coder.h"
#import "PGPPacketHelper.h"
#import "PEMHelper.h"

#define publicArmorBegin @"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
#define publicArmorEnd @"-----END PGP PUBLIC KEY BLOCK-----\n"
#define privateArmorBegin @"-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
#define privateArmorEnd @"-----END PGP PRIVATE KEY BLOCK-----\n"
#define pgpMessageBegin @"-----BEGIN PGP MESSAGE-----\n"
#define pgpMessageEnd @"-----END PGP MESSAGE-----\n"
#define keyFileComment @"Comment"

@implementation PGPArmorHelper

+ (BOOL)isArmored:(NSString *)fileContent {
    if ([fileContent containsString:publicArmorBegin] ||
        [fileContent containsString:publicArmorEnd] ||
        [fileContent containsString:privateArmorBegin] ||
        [fileContent containsString:privateArmorEnd] ||
        [fileContent containsString:keyFileComment] ||
        [fileContent containsString:pgpMessageBegin] ||
        [fileContent containsString:pgpMessageEnd]) {
        return YES;
    } else {
        return NO;
    }
}

+ (NSData *)removeArmorFromKeyFile:(NSURL*)fileUrl {
    NSError* error;
    NSString* contentOfURL = [NSString stringWithContentsOfURL:fileUrl encoding:NSUTF8StringEncoding error:&error];
    if (error) {
        NSLog(@"Error while reading KeyFile: %@\nUserInfo: %@", error, error.userInfo);
        return NULL;
    } else {
        return [PGPArmorHelper removeArmorFromKeyFileString:contentOfURL];
    }
}

+ (NSData *)removeArmorFromKeyFileString:(NSString*)fileContent {
    if ([PGPArmorHelper isArmored:fileContent]) {
        NSString *encodedBase64String = [PGPArmorHelper removeArmorFromString:fileContent];
        return [Base64Coder getDecodedBase64StringFromString:encodedBase64String];
    } else {
        return [NSData dataWithBytes:[fileContent UTF8String] length:fileContent.length];
    }
}

+ (NSString*)removeArmorFromString:(NSString*)string {
    string = [string stringByReplacingOccurrencesOfString:publicArmorBegin withString:@""];
    string = [string stringByReplacingOccurrencesOfString:publicArmorEnd withString:@""];
    string = [string stringByReplacingOccurrencesOfString:privateArmorBegin withString:@""];
    string = [string stringByReplacingOccurrencesOfString:privateArmorEnd withString:@""];
    string = [string stringByReplacingOccurrencesOfString:pgpMessageBegin withString:@""];
    string = [string stringByReplacingOccurrencesOfString:pgpMessageEnd withString:@""];
    
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
    
    [[PGPPacketHelper sharedManager] addPacketWithPGPPacket:packet];
    
    if (length <= pos+packet_length+1){
        return 0; //End of bytes
    }
    
    return pos+packet_length;
}

+ (NSData*)extractPublicKeyFromPacket:(PGPPacket*) packet pos:(int*) position {
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
    if (algorithm != 1) {
        return NULL;
    }
    NSLog(@"PGP public key algorithm: %d", algorithm);
    
    char* bmpi = packet.bytes + pos;
    int p = 0;
    
    // get key data
    double key_len = (bmpi[p] << 8) | bmpi[p+1];
    int key_byteLen = ceil(key_len / 8);
    
    unsigned char rsaKey[key_byteLen+4];
    
    rsaKey[0] = key_byteLen >> 24;
    rsaKey[1] = key_byteLen >> 16;
    rsaKey[2] = key_byteLen >> 8;
    rsaKey[3] = key_byteLen;
    for (int i = 2; i < key_byteLen+2; i++) {
        rsaKey[i+2] = bmpi[i];
    }
    
    p = 2+key_byteLen;
    
    // get public exponent
    double exp_len = (bmpi[p] << 8) | bmpi[p+1];
    int exp_byteLen = ceil(exp_len / 8);
    
    unsigned char pub_exp[exp_byteLen+4];
    
    pub_exp[0] = exp_byteLen >> 24;
    pub_exp[1] = exp_byteLen >> 16;
    pub_exp[2] = exp_byteLen >> 8;
    pub_exp[3] = exp_byteLen;
    for (int i = 2; i < exp_byteLen+2; i++) {
        pub_exp[i+2] = bmpi[p+i];
    }
    
    p += 2+exp_byteLen;
    
    BIGNUM *keyData, *exponentData;
    keyData = BN_mpi2bn(rsaKey, key_byteLen+4, NULL);
    if (keyData->neg) {
        BN_set_bit(keyData, ((int) key_len) - 1);
        keyData->neg = 0;
    }
    exponentData = BN_mpi2bn(pub_exp, exp_byteLen+4, NULL);
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
    
    if (position != NULL) {
        *position = pos + p;
    }
    
    return [PEMHelper writeKeyToPEMWithRSA:pubKey andIsPrivate:NO];
}

+ (NSData *)extractPrivateKeyFromPacket:(PGPPacket *)packet{
    if (packet.tag != 5){
        //Wrong packet
        return NULL;
    }
    
    int pos = 0;
    unsigned char* bmpi = NULL;
    int p = 0;
    
    //Extract PublicKey from packet
    RSA* secKey = [PEMHelper readPUBKEYFromPEMdata:[PGPArmorHelper extractPublicKeyFromPacket:packet pos:&pos]];
    
    int s2k = [packet bytes][pos++];
    
    switch (s2k) {
        case 0:
            // Indicates that the secret-key data is not encrypted
            // Get MPIs
            bmpi = (unsigned char*)[packet bytes] + pos;
            
            for (int i = 0; i < 4 && p < ([packet length] - pos); i++) {
                double len = bmpi[p] << 8 | bmpi[p+1];
                int byte_len = ceil(len/8);
                
                unsigned char mpi[byte_len+4];
                mpi[0] = byte_len >> 24;
                mpi[1] = byte_len >> 16;
                mpi[2] = byte_len >> 8;
                mpi[3] = byte_len;
                for (int j = 4; j < byte_len+4; j++) {
                    mpi[j] = bmpi[p+j-2];
                }
                BIGNUM* tmp = BN_mpi2bn(mpi, byte_len+4, NULL);
                if (tmp->neg) {
                    BN_set_bit(tmp, ((int) len) - 1);
                    tmp->neg = 0;
                }
                switch (i) {
                    case 0:
                        secKey->d = tmp;
                        break;
                    case 1:
                        secKey->p = tmp;
                        break;
                    case 2:
                        secKey->q = tmp;
                        break;
                    default:
                        break;
                }
                p += 2+byte_len;
            }
            
            //calculate missing secret key parts
            secKey->dmp1 = BN_new();
            secKey->dmq1 = BN_new();
            secKey->iqmp = BN_new();
            BIGNUM* m = BN_new();
            BN_CTX* ctx = BN_CTX_new();
            
            // calculate dmp1 = d mod (p-1)
            BN_sub(m, secKey->p, BN_value_one());
            BN_mod(secKey->dmp1, secKey->d, m, ctx);
            
            // calculate dmq1 = d mod (q-1)
            BN_sub(m, secKey->q, BN_value_one());
            BN_mod(secKey->dmq1, secKey->d, m, ctx);
            
            // calculate iqmp = q^-1 mod p?
            BN_mod_inverse(secKey->iqmp, secKey->q, secKey->p, ctx);
            
            BN_CTX_free(ctx);
            
            break;
        case 255:
        case 254:
            // Indicates that a string-to-key specifier is being given
            break;
        default:
            // Any other value is a symmetric-key encryption algorithm identifier
            break;
    }
    
    NSData* result = [PEMHelper writeKeyToPEMWithRSA:secKey andIsPrivate:YES];
    RSA_free(secKey);
    
    return result;
}

+ (NSData *)extractEncryptedSymmetricSessionKeyFromPacket:(PGPPacket *)packet {
    int pos = 0;
    int version = [packet bytes][pos++];
    unsigned long long pubKeyID = (unsigned long long)[packet bytes][pos] << 56 |
                    (unsigned long long)[packet bytes][pos+1] << 48 |
                    (unsigned long long)[packet bytes][pos+2] << 40 |
                    (unsigned long long)[packet bytes][pos+3] << 32 |
                    [packet bytes][pos+4] << 24 |
                    [packet bytes][pos+5] << 16 |
                    [packet bytes][pos+6] << 8 |
                    [packet bytes][pos+7];
    
    
    return NULL;
}



+ (NSData*)extractSymmetricEncryptedIntegrityProtectedDataFromPacket:(PGPPacket *)packet{
    int pos = 0;
    int version = [packet bytes][pos++]; //RFC: A one-octet version number.  The only currently defined value is 1.
    
    if (version != 1){
       //Error
    }
    
    //Encrypted data, the output of the selected symmetric-key cipher operating in Cipher Feedback mode with shift amount equal to the block size of the cipher (CFB-n where n is the block size)
    
}
@end
