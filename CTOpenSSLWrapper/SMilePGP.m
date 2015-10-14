//
//  SMilePGP.m
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 05.10.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "SMilePGP.h"

#import "PGPArmorHelper.h"
#import "PGPPacketParser.h"
#import "PGPMessageBuilder.h"

#import "CTOpenSSLAsymmetricEncryption.h"
#import "CTOpenSSLSymmetricEncryption.h"
#import "NSData+Godzippa.h"

@implementation SMilePGP

- (PGPKey*)importPGPKeyFromArmouredFile:(NSData*)fileContent {
    NSString* fileContentString = [[NSString alloc] initWithData:fileContent encoding:NSUTF8StringEncoding];
    BOOL isPrivate = [fileContentString containsString:@"-----BEGIN PGP PRIVATE KEY BLOCK-----"];
    NSData* packets = [PGPArmorHelper removeArmorFromKeyFileString:fileContentString];
    PGPPacketParser* parser = [[PGPPacketParser alloc] init];
    int nextpos = 0;
    do {
        nextpos = [parser extractPacketsFromBytes:packets atPostion:nextpos];
    } while (nextpos > 0);
    if (isPrivate) {
        PGPSecretKeyPacket* mainKeyPacket = [[parser getPacketsWithTag:5] objectAtIndex:0];
        int keyLen = [[[[mainKeyPacket pubKey] mpis] objectAtIndex:0] length]*8;
        NSMutableArray* userIDs = [[NSMutableArray alloc] init];
        for (int i = 0; i < [[parser getPacketsWithTag:13] count]; i++) {
            PGPUserIDPacket* userIDPacket = [[parser getPacketsWithTag:13] objectAtIndex:i];
            [userIDs addObject:[userIDPacket userID]];
        }
        NSData* keyID = [parser generateKeyID:[mainKeyPacket pubKey]];
        NSData* fingerprint = [parser generateFingerprint:[mainKeyPacket pubKey]];
        BOOL encrypted = (mainKeyPacket.s2k != 0);
        PGPKey* mainKey = [[PGPKey alloc] initWithKeyID:keyID andWithFingerPrint:fingerprint andWithUserIDs:userIDs andWithKeyLength:keyLen andWithKeyData:mainKeyPacket andIsPrivate:isPrivate andIsEncrypted:encrypted];
        for (int i = 0; i < [[parser getPacketsWithTag:7] count]; i++) {
            PGPSecretKeyPacket *subKeyPacket = [[parser getPacketsWithTag:7] objectAtIndex:i];
            NSData* subKeyID = [parser generateKeyID:[subKeyPacket pubKey]];
            NSData* subFingerprint = [parser generateFingerprint:[subKeyPacket pubKey]];
            PGPKey* subKey = [[PGPKey alloc] initWithKeyID:subKeyID andWithFingerPrint:subFingerprint andWithUserIDs:userIDs andWithKeyLength:keyLen andWithKeyData:subKeyPacket andIsPrivate:isPrivate andIsEncrypted:encrypted];
            [[mainKey subKeys] addObject:subKey];
        }
        return mainKey;
    } else {
        PGPPublicKeyPacket* mainKeyPacket = [[parser getPacketsWithTag:6] objectAtIndex:0];
        int keyLen = [[[mainKeyPacket mpis] objectAtIndex:0] length]*8;
        NSMutableArray* userIDs = [[NSMutableArray alloc] init];
        for (int i = 0; i < [[parser getPacketsWithTag:13] count]; i++) {
            PGPUserIDPacket* userIDPacket = [[parser getPacketsWithTag:13] objectAtIndex:i];
            [userIDs addObject:[userIDPacket userID]];
        }
        NSData* keyID = [parser generateKeyID:mainKeyPacket];
        NSData* fingerprint = [parser generateFingerprint:mainKeyPacket];
        PGPKey* mainKey = [[PGPKey alloc] initWithKeyID:keyID andWithFingerPrint:fingerprint andWithUserIDs:userIDs andWithKeyLength:keyLen andWithKeyData:mainKeyPacket andIsPrivate:isPrivate andIsEncrypted:false];
        for (int i = 0; i < [[parser getPacketsWithTag:14] count]; i++) {
            PGPPublicKeyPacket *subKeyPacket = [[parser getPacketsWithTag:14] objectAtIndex:i];
            NSData* subKeyID = [parser generateKeyID:subKeyPacket];
            NSData* subFingerprint = [parser generateFingerprint:subKeyPacket];
            PGPKey* subKey = [[PGPKey alloc] initWithKeyID:subKeyID andWithFingerPrint:subFingerprint andWithUserIDs:userIDs andWithKeyLength:keyLen andWithKeyData:subKeyPacket andIsPrivate:isPrivate andIsEncrypted:false];
            [[mainKey subKeys] addObject:subKey];
        }
        return mainKey;
    }
}

- (NSString*)getKeyIDFromArmoredPGPMessage:(NSData*)messageData {
    NSData* packets = [PGPArmorHelper removeArmorFromKeyFileString:[[NSString alloc] initWithData:messageData encoding:NSUTF8StringEncoding]];
    PGPPacketParser* parser = [[PGPPacketParser alloc] init];
    int nextpos = 0;
    do {
        nextpos = [parser extractPacketsFromBytes:packets atPostion:nextpos];
    } while (nextpos > 0);
    if ([[parser getPacketsWithTag:1] count] == 0) {
        return NULL;
    }
    PGPPublicKeyEncryptedSessionKeyPacket* packet = [[parser getPacketsWithTag:1] objectAtIndex:0];
    NSData* keyID = [NSData dataWithBytes:(const void *)[packet pubKeyID] length:8];
    NSString* ret = [[keyID description] uppercaseString];
    return [ret substringWithRange:NSMakeRange(1, [ret length]-2)];
}

- (NSData*)decryptPGPMessageWithKey:(PGPKey*)secKey fromArmouredFile:(NSData*)fileContent {
    return [self decryptPGPMessageWithKey:secKey fromArmouredFile:fileContent WithPassphrase:NULL];
}

- (NSData*)decryptPGPMessageWithKey:(PGPKey*)secKey fromArmouredFile:(NSData*)fileContent WithPassphrase:(NSString*)passphrase {
    NSData* packets = [PGPArmorHelper removeArmorFromKeyFileString:[[NSString alloc] initWithData:fileContent encoding:NSUTF8StringEncoding]];
    PGPPacketParser* parser = [[PGPPacketParser alloc] init];
    int nextpos = 0;
    nextpos = [parser extractPacketsFromBytes:packets atPostion:nextpos];
    if (nextpos == -1) {
        return NULL;
    }
    if ([[parser getPacketsWithTag:1] count] > 0 || [[parser getPacketsWithTag:9] count] > 0 || [[parser getPacketsWithTag:18] count] > 0) {
        // Encrypted Message
        if ([[parser getPacketsWithTag:1] count] == 0) {
            return NULL; // not supported
        }
        PGPPublicKeyEncryptedSessionKeyPacket* encSessionKeyPacket = [[parser getPacketsWithTag:1] objectAtIndex:0];
        NSData* encSessionKey = [[encSessionKeyPacket mpis] objectAtIndex:0];
        
        NSData* keyID = [NSData dataWithBytes:(const void *)[encSessionKeyPacket pubKeyID] length:8];
        NSData* secretKey = NULL;
        if ([[secKey keyID] isEqualToData:keyID]) {
            if ([secKey encryted]) {
                secretKey = [secKey decryptKeyWithPassphrase:passphrase];
            } else {
                secretKey = [parser getPEMFromSecretKeyPacket:(PGPSecretKeyPacket*)[secKey keyData]];
            }
        } else {
            for (int i = 0; i < [[secKey subKeys] count]; i++) {
                PGPKey* subKey = [[secKey subKeys] objectAtIndex:i];
                if ([[subKey keyID] isEqualToData:keyID]) {
                    if ([secKey encryted]) {
                        secretKey = [subKey decryptKeyWithPassphrase:passphrase];
                    } else {
                        secretKey = [parser getPEMFromSecretKeyPacket:(PGPSecretKeyPacket*)[subKey keyData]];
                    }
                    break;
                }
            }
        }
        
        if (secretKey == NULL) {
            return NULL;
        }
        
        NSData* decryptedSessionKey = CTOpenSSLRSADecrypt(secretKey, encSessionKey);
        if (decryptedSessionKey == NULL) {
            return NULL;
        }
        
        NSData* sessionKey = [NSData dataWithBytes:decryptedSessionKey.bytes+1 length:decryptedSessionKey.length-3];
        // Check checksum
        int checksum = ((unsigned char*)[decryptedSessionKey bytes])[[decryptedSessionKey length]-2] << 8 | ((unsigned char*)[decryptedSessionKey bytes])[[decryptedSessionKey length]-1];
        int valueToCheck = 0;
        for (int i = 0; i < [sessionKey length]; i++) {
            valueToCheck += ((unsigned char*)[sessionKey bytes])[i];
        }
        valueToCheck %= 65536;
        if (checksum != valueToCheck) {
            return NULL;
        }
        
        nextpos = [parser extractPacketsFromBytes:packets atPostion:nextpos];
        if (nextpos == -1) {
            return NULL;
        }
        NSData* decryptedData;
        if ([[parser getPacketsWithTag:9] count] > 0) {
            PGPSymmetricallyEncryptedDataPacket* encData = [[parser getPacketsWithTag:9] objectAtIndex:0];
            int algorithm = ((unsigned char*)[decryptedSessionKey bytes])[0];
            switch (algorithm) {
                case 9:
                    if (!CTOpenSSLSymmetricDecryptAES256CFB(sessionKey, [encData encryptedData], &decryptedData)) {
                        return NULL;
                    }
                    break;
                default:
                    // all other values are not supported yet
                    return NULL;
                    break;
            }
        } else if ([[parser getPacketsWithTag:18] count] > 0) {
            PGPSymmetricEncryptedIntegrityProtectedDataPacket* encData = [[parser getPacketsWithTag:18] objectAtIndex:0];
            int algorithm = ((unsigned char*)[decryptedSessionKey bytes])[0];
            switch (algorithm) {
                case 9:
                    if (!CTOpenSSLSymmetricDecryptAES256CFB(sessionKey, [encData encryptedData], &decryptedData)) {
                        return NULL;
                    }
                    break;
                default:
                    // all other values are not supported yet
                    return NULL;
                    break;
            }
            decryptedData = [encData checkPacketFromDecryptedData:decryptedData];
            if (decryptedData == NULL) {
                return NULL;
            }
        } else {
            return NULL;
        }
        memset((void*)[decryptedSessionKey bytes], 0, [decryptedSessionKey length]);
        memset((void*)[sessionKey bytes], 0, [sessionKey length]);
        nextpos = 0;
        if ([parser extractPacketsFromBytes:decryptedData atPostion:nextpos] == -1) {
            return NULL;
        }
        if ([[parser getPacketsWithTag:8] count] > 0) {
            PGPCompressedDataPacket* compressedDataPacket = [[parser getPacketsWithTag:8] objectAtIndex:0];
            NSData* plainData;
            switch ([compressedDataPacket algorithm]) {
                case 1:
                    // not supported yet
                    return NULL;
                    break;
                case 2:
                    plainData = [[compressedDataPacket compressedData] dataByGZipDecompressingDataWithWindowSize:32 error:NULL];
                    if ([parser extractPacketsFromBytes:plainData atPostion:nextpos] == -1) {
                        return NULL;
                    }
                    return [[[parser getPacketsWithTag:11] objectAtIndex:0] literalData];
                    break;
                case 3:
                    // not supported yet
                    return NULL;
                    break;
                default:
                    return NULL;
                    break;
            }
        } else if ([[parser getPacketsWithTag:11] count] > 0) {
            return [[[parser getPacketsWithTag:11] objectAtIndex:0] literalData];
        } else {
            return NULL;
        }
    } else if ([[parser getPacketsWithTag:8] count] > 0) {
        // Compressed Message
        PGPCompressedDataPacket* compressedDataPacket = [[parser getPacketsWithTag:8] objectAtIndex:0];
        NSData* plainData;
        switch ([compressedDataPacket algorithm]) {
            case 1:
                // not supported yet
                return NULL;
                break;
            case 2:
                plainData = [[compressedDataPacket compressedData] dataByGZipDecompressingDataWithWindowSize:32 error:NULL];
                if ([parser extractPacketsFromBytes:plainData atPostion:nextpos] == -1) {
                    return NULL;
                }
                return [[[parser getPacketsWithTag:11] objectAtIndex:0] literalData];
                break;
            case 3:
                // not supported yet
                return NULL;
                break;
            default:
                return NULL;
                break;
        }
    } else if ([[parser getPacketsWithTag:11] count] > 0) {
        // Literal Message
        return [[[parser getPacketsWithTag:11] objectAtIndex:0] literalData];
    } else {
        // Signed Message
        return NULL; // Not supported yet
    }
}

- (NSData*)buildPGPMessageFromData:(NSData*)data WithKey:(PGPKey*)key {
    PGPMessageBuilder* builder = [[PGPMessageBuilder alloc] init];
    PGPKey* keyToEncrypt;
    if ([[key subKeys] count] > 0) {
        keyToEncrypt = [[key subKeys] objectAtIndex:0];
    } else {
        keyToEncrypt = key;
    }
    PGPPacketParser* parser = [[PGPPacketParser alloc] init];
    PGPPublicKeyPacket* pubKey;
    if (keyToEncrypt.isPrivate) {
        pubKey = [((PGPSecretKeyPacket*)[keyToEncrypt keyData]) pubKey];
    } else {
        pubKey = (PGPPublicKeyPacket*)[keyToEncrypt keyData];
    }
    NSData* keyData = [parser getPEMFromPublicKeyPacket:pubKey];
    NSData* messageData = [builder buildPGPEncryptedMessageFromData:data withPGPPublicKey:keyData andPubKeyID:(unsigned char*)[[keyToEncrypt keyID] bytes]];
    NSData* messageChecksum = [builder getChecksumForPGPMessageData:messageData];
    return [builder buildArmouredPGPMessageFromMessageData:messageData andChecksum:messageChecksum];
}

@end
