//
//  PGPMessageBuilder.m
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 25.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPMessageBuilder.h"

#import "NSData+Godzippa.h"
#import "CTOpenSSLDigest.h"
#import "CTOpenSSLSymmetricEncryption.h"
#import "CTOpenSSLAsymmetricEncryption.h"
#import "Base64Coder.h"

#import <openssl/rand.h>

#define CRC24_INIT 0xB704CEL
#define CRC24_POLY 0x1864CFBL

typedef long crc24;
static crc24 crc_octets(unsigned char *octets, size_t len)
{
    crc24 crc = CRC24_INIT;
    int i;
    while (len--) {
        crc ^= (*octets++) << 16;
        for (i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000)
                crc ^= CRC24_POLY;
        }
    }
    return crc & 0xFFFFFFL;
}

@implementation PGPMessageBuilder

- (NSData*)buildPGPEncryptedMessageFromData:(NSData *)dataToEncrypt withPGPPublicKey:(NSData*)pubKey andPubKeyID:(unsigned char*)pubKeyID {
    // session key
    unsigned char key[32];
    
    if (!RAND_bytes(key, sizeof(key))) {
        /* OpenSSL reports a failure, act accordingly */
    }
    NSData* sessionKey = [NSData dataWithBytes:(const void*)key length:sizeof(key)];
    
    // packets
    PGPLiteralDataPacket* dataPacket = [self buildLiteralDataPacketFromData:dataToEncrypt];
    //PGPCompressedDataPacket* compressedData = [self buildCompressedDataPacketFromData:[self getbytesFromPacket:dataPacket]];
    PGPSymmetricEncryptedIntegrityProtectedDataPacket* encryptedData = [self buildSymmetricEncryptedIntegrityProtectedDataPacketWithBytes:[self getbytesFromPacket:dataPacket] andSessionKey:sessionKey];
    PGPPublicKeyEncryptedSessionKeyPacket* encryptedKey = [self buildPublicKeyEncryptedSessionKeyPacketWithPGPPublicKey:pubKey andSessionKey:sessionKey andPubKeyID:pubKeyID];
    
    NSData* encryptedDataBytes = [self getbytesFromPacket:encryptedData];
    NSData* encryptedKeyBytes = [self getbytesFromPacket:encryptedKey];
    
    int length = [encryptedDataBytes length] + [encryptedKeyBytes length];
    unsigned char* pgpmessage = malloc(length);
    if (pgpmessage == NULL) {
        return NULL;
    }
    for (int i = 0; i < [encryptedKeyBytes length]; i++) {
        pgpmessage[i] = ((unsigned char*)[encryptedKeyBytes bytes])[i];
    }
    for (int i = 0; i < [encryptedDataBytes length]; i++) {
        pgpmessage[i+[encryptedKeyBytes length]] = ((unsigned char*)[encryptedDataBytes bytes])[i];
    }
    NSData* ret = [NSData dataWithBytes:(const void *)pgpmessage length:length];
    free(pgpmessage);
    return ret;
}

- (NSData*)getChecksumForPGPMessageData:(NSData*)pgpmessage {
    crc24 checksum = crc_octets((unsigned char *)[pgpmessage bytes], [pgpmessage length]);
    unsigned char bytes[3];
    bytes[0] = checksum >> 16;
    bytes[1] = checksum >> 8;
    bytes[2] = checksum;
    return [NSData dataWithBytes:(const void *)bytes length:3];
}

- (NSData*)buildArmouredPGPMessageFromMessageData:(NSData *)messageData andChecksum:(NSData *)checksum {
    NSData* encodedMessage = [Base64Coder encodeBase64String:messageData];
    NSData* encodedChecksum = [Base64Coder encodeBase64String:checksum];
    NSMutableData* armouredMessage = [[@"-----BEGIN PGP MESSAGE-----\n" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
    [armouredMessage appendData:encodedMessage];
    [armouredMessage appendData:[@"=" dataUsingEncoding:NSUTF8StringEncoding]];
    [armouredMessage appendData:encodedChecksum];
    [armouredMessage appendData:[@"-----END PGP MESSAGE-----" dataUsingEncoding:NSUTF8StringEncoding]];
    return armouredMessage;
}

- (PGPLiteralDataPacket*)buildLiteralDataPacketFromData:(NSData*)dataToEncrypt {
    PGPLiteralDataPacket *packet = [[PGPLiteralDataPacket alloc] init];
    // Header
    packet.tag = 11;
    packet.format = 1;
    
    // Data
    packet.formatType = 0x74;
    packet.fileName = @"";
    packet.date = 0;
    packet.literalData = dataToEncrypt;
    
    int length = 1+1+0+4+[dataToEncrypt length];
    unsigned char* bytes = malloc(length);
    if (bytes == NULL) {
        return NULL;
    }
    bytes[0] = (unsigned char) packet.formatType;
    bytes[1] = '\0';
    bytes[2] = (unsigned char)(packet.date >> 24);
    bytes[3] = (unsigned char)(packet.date >> 16);
    bytes[4] = (unsigned char)(packet.date >> 8);
    bytes[5] = (unsigned char)packet.date;
    for (int i = 0; i < [dataToEncrypt length]; i++) {
        bytes[i+6] = ((unsigned char*)[dataToEncrypt bytes])[i];
    }
    
    packet.bytes = [NSData dataWithBytes:(const void *)bytes length:length];
    
    free(bytes);
    
    return packet;
}

- (PGPCompressedDataPacket*)buildCompressedDataPacketFromData:(NSData*)dataToCompress {
    PGPCompressedDataPacket *packet = [[PGPCompressedDataPacket alloc] init];
    // Header
    packet.tag = 8;
    packet.format = 1;
    
    // Data
    packet.algorithm = 2;
    NSError* error;
    packet.compressedData = [dataToCompress dataByGZipCompressingWithError:&error];
    int length = 1+[packet.compressedData length];
    unsigned char* bytes = malloc(length);
    if (bytes == NULL) {
        return NULL;
    }
    bytes[0] = (unsigned char)packet.algorithm;
    for (int i = 0; i < [packet.compressedData length]; i++) {
        bytes[i+1] = ((unsigned char*)[packet.compressedData bytes])[i];
    }
    
    packet.bytes = [NSData dataWithBytes:(const void *)bytes length:length];
    
    free(bytes);
    
    return packet;
}

- (PGPSymmetricEncryptedIntegrityProtectedDataPacket*)buildSymmetricEncryptedIntegrityProtectedDataPacketWithBytes:(NSData*)dataToEncrypt andSessionKey:(NSData*)sessionKey {
    PGPSymmetricEncryptedIntegrityProtectedDataPacket *packet = [[PGPSymmetricEncryptedIntegrityProtectedDataPacket alloc] init];
    // Header
    packet.tag = 18;
    packet.format = 1;
    
    // Data
    packet.version = 1;
    
    unsigned char randomBytes[16];
    if (!RAND_bytes(randomBytes, sizeof(randomBytes))) {
        /* OpenSSL reports a failure, act accordingly */
    }
    int length = 16+2+[dataToEncrypt length]+2;
    unsigned char* data = malloc(length+20);
    if (data == NULL) {
        return NULL;
    }
    for (int i = 0; i < 16; i++) {
        data[i] = randomBytes[i];
    }
    data[16] = randomBytes[14];
    data[17] = randomBytes[15];
    for (int i = 0; i < [dataToEncrypt length]; i++) {
        data[i+18] = ((unsigned char*)[dataToEncrypt bytes])[i];
    }
    data[length-2] = 0xd3;
    data[length-1] = 0x14;
    
    NSData* dataToHash = [NSData dataWithBytes:(const void *)data length:length];
    unsigned char* sha1 = (unsigned char*)[CTOpenSSLGenerateDigestFromData(dataToHash, CTOpenSSLDigestTypeSHA1) bytes];
    
    for (int i = 0; i < 20; i++) {
        data[length+i] = sha1[i];
    }
    
    NSData* encryptedData = NULL;
    if (!CTOpenSSLSymmetricEncryptAES256CFB(sessionKey, [NSData dataWithBytes:(const void *)data length:length+20], &encryptedData)) {
        return NULL;
    }
    
    length = [encryptedData length]+1;
    unsigned char* bytes = malloc(length);
    if (bytes == NULL) {
        return NULL;
    }
    bytes[0] = packet.version;
    for (int i = 1; i < length; i++) {
        bytes[i] = ((unsigned char*)[encryptedData bytes])[i-1];
    }
    
    packet.bytes = [NSData dataWithBytes:(const void *)bytes length:length];
    
    free(data);
    free(bytes);
    
    return packet;
}

- (PGPPublicKeyEncryptedSessionKeyPacket*)buildPublicKeyEncryptedSessionKeyPacketWithPGPPublicKey:(NSData*)pubKey andSessionKey:(NSData*)sessionKey andPubKeyID:(unsigned char*)pubKeyID {
    PGPPublicKeyEncryptedSessionKeyPacket *packet = [[PGPPublicKeyEncryptedSessionKeyPacket alloc] init];
    
    // Header
    packet.tag = 1;
    packet.format = 1;
    
    // Data
    packet.version = 3;
    packet.pubKeyID = calloc(8, sizeof(char));
    for (int i = 0; i < 8; i++) {
        packet.pubKeyID[i] = pubKeyID[i];
    }
    packet.algorithm = 1;
    
    // generating m
    int length = [sessionKey length]+3;
    unsigned char m[length];
    int checksum = 0;
    m[0] = 0x9;
    for (int i = 0; i < [sessionKey length]; i++) {
        unsigned char tmp = ((unsigned char*)[sessionKey bytes])[i];
        checksum += tmp;
        m[i+1] = tmp;
    }
    checksum %= 65536;
    m[length-2] = (unsigned char)(checksum >> 8);
    m[length-1] = (unsigned char)checksum;
    
    NSData* encryptedSessionKey = CTOpenSSLRSAEncrypt(pubKey, [NSData dataWithBytes:(const void *)m length:length]);
    for (int i = 0; i < length; i++) {
        m[i] = '\0';
    }
    [packet.mpis addObject:encryptedSessionKey];
    
    length = 1+8+1+2+[encryptedSessionKey length];
    unsigned char bytes[length];
    int pos = 0;
    bytes[pos++] = packet.version;
    for (int i = 0; i < 8; i++) {
        bytes[i+pos] = packet.pubKeyID[i];
    }
    pos += 8;
    bytes[pos++] = packet.algorithm;
    int bitLen = [encryptedSessionKey length] * 8;
    bytes[pos++] = bitLen >> 8;
    bytes[pos++] = bitLen;
    for (int i = 0; i < [encryptedSessionKey length]; i++) {
        bytes[i+pos] = ((unsigned char*)[encryptedSessionKey bytes])[i];
    }
    
    packet.bytes = [NSData dataWithBytes:(const void*)bytes length:length];
    
    return packet;
}

- (NSData*)getbytesFromPacket:(PGPPacket*)packet {
    unsigned char packet_header = 0;
    unsigned char length_octets[5];
    int octetcount = 0;
    
    int packet_length = [packet.bytes length];
    if (packet.format) {
        // new format
        packet_header = 0xc0 | packet.tag;
        
        if (packet_length < 192) {
            length_octets[0] = (unsigned char)packet_length;
            octetcount = 1;
        } else if (packet_length > 191 && packet_length < 8384) {
            length_octets[0] = (unsigned char)(((packet_length-192) >> 8)+192);
            length_octets[1] = (unsigned char)(packet_length - 192);
            octetcount = 2;
        } else if (packet_length > 8383) {
            length_octets[0] = 255;
            length_octets[1] = (unsigned char) (packet_length >> 24);
            length_octets[2] = (unsigned char) (packet_length >> 16);
            length_octets[3] = (unsigned char) (packet_length >> 8);
            length_octets[4] = (unsigned char) packet_length;
            octetcount = 5;
        }
    } else {
        // old format
        packet_header = 0x80 | packet.tag << 2 | 0x0;
        if (packet_length <= 0xff) {
            length_octets[0] = (unsigned char)packet_length;
            octetcount = 1;
        }else if (packet_length > 0xff && packet_length <= 0xffff) {
            packet_header |= 0x1;
            length_octets[0] = (unsigned char)(packet_length >> 8);
            length_octets[1] = (unsigned char)packet_length;
            octetcount = 2;
        } else if (packet_length > 0xffff && packet_length <= 0xffffffff) {
            packet_header |= 0x2;
            length_octets[0] = (unsigned char)(packet_length >> 24);
            length_octets[1] = (unsigned char)(packet_length >> 16);
            length_octets[2] = (unsigned char)(packet_length >> 8);
            length_octets[3] = (unsigned char)packet_length;
            octetcount = 4;
        } else {
            packet_header |= 0x3;
        }
    }
    
    packet_length += 1+octetcount;
    unsigned char packet_bytes[packet_length];
    packet_bytes[0] = packet_header;
    for (int i = 0; i < octetcount; i++) {
        packet_bytes[i+1] = length_octets[i];
    }
    for (int i = 0; i < [packet.bytes length]; i++) {
        packet_bytes[i+1+octetcount] = ((unsigned char*)[packet.bytes bytes])[i];
    }
    
    return [[NSData alloc] initWithBytes:(const void*)packet_bytes length:packet_length];
}

@end
