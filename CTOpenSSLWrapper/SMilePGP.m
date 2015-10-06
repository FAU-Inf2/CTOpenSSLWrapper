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
        PGPUserIDPacket* userIDPacket = [[parser getPacketsWithTag:13] objectAtIndex:0];
        NSData* keyID = [parser generateKeyID:[mainKeyPacket pubKey]];
        BOOL encrypted = (mainKeyPacket.s2k != 0);
        PGPKey* mainKey = [[PGPKey alloc] initWithKeyID:keyID andWithUserID:[userIDPacket userID] andWithKeyData:mainKeyPacket andIsPrivate:isPrivate andIsEncrypted:encrypted];
        for (int i = 0; i < [[parser getPacketsWithTag:7] count]; i++) {
            PGPSecretKeyPacket *subKeyPacket = [[parser getPacketsWithTag:7] objectAtIndex:i];
            NSData* subKeyID = [parser generateKeyID:[subKeyPacket pubKey]];
            PGPKey* subKey = [[PGPKey alloc] initWithKeyID:subKeyID andWithUserID:[userIDPacket userID] andWithKeyData:subKeyPacket andIsPrivate:isPrivate andIsEncrypted:encrypted];
            [[mainKey subKeys] addObject:subKey];
        }
        return mainKey;
    } else {
        PGPPublicKeyPacket* mainKeyPacket = [[parser getPacketsWithTag:6] objectAtIndex:0];
        PGPUserIDPacket* userIDPacket = [[parser getPacketsWithTag:13] objectAtIndex:0];
        NSData* keyID = [parser generateKeyID:mainKeyPacket];
        PGPKey* mainKey = [[PGPKey alloc] initWithKeyID:keyID andWithUserID:[userIDPacket userID] andWithKeyData:mainKeyPacket andIsPrivate:isPrivate andIsEncrypted:false];
        for (int i = 0; i < [[parser getPacketsWithTag:14] count]; i++) {
            PGPPublicKeyPacket *subKeyPacket = [[parser getPacketsWithTag:14] objectAtIndex:i];
            NSData* subKeyID = [parser generateKeyID:subKeyPacket];
            PGPKey* subKey = [[PGPKey alloc] initWithKeyID:subKeyID andWithUserID:[userIDPacket userID] andWithKeyData:subKeyPacket andIsPrivate:isPrivate andIsEncrypted:false];
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
    do {
        nextpos = [parser extractPacketsFromBytes:packets atPostion:nextpos];
    } while (nextpos > 0);
    PGPPublicKeyEncryptedSessionKeyPacket* packet = [[parser getPacketsWithTag:1] objectAtIndex:0];
    NSData* encryptedSessionKey = [[packet mpis] objectAtIndex:0];
    
    NSData* keyID = [NSData dataWithBytes:(const void *)[packet pubKeyID] length:8];
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
    
    NSData* decryptedSessionKey = CTOpenSSLRSADecrypt(secretKey, encryptedSessionKey);
    
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
    
    NSData* ret = NULL;
    PGPSymmetricEncryptedIntegrityProtectedDataPacket* p = [[parser getPacketsWithTag:18] objectAtIndex:0];
    NSData* encrypted = [p encryptedData];
    CTOpenSSLSymmetricDecryptAES256CFB(sessionKey, encrypted, &ret);
    
    ret = [p checkPacketFromDecryptedData:ret];
    
    nextpos = 0;
    do {
        nextpos = [parser extractPacketsFromBytes:ret atPostion:nextpos];
    } while (nextpos > 0);
    
    PGPCompressedDataPacket *cp = [[parser getPacketsWithTag:8] objectAtIndex:0];
    
    NSError *error = NULL;
    NSData* plain = [[cp compressedData] dataByGZipDecompressingDataWithWindowSize:32 error:&error];
    if (error != NULL) {
        NSLog(@"%@", error.description);
    }
    
    nextpos = 0;
    do {
        nextpos = [parser extractPacketsFromBytes:plain atPostion:nextpos];
    } while (nextpos > 0);
    return [[[parser getPacketsWithTag:11] objectAtIndex:0] literalData];
}

- (NSData*)buildPGPMessageFromData:(NSData*)data WithKey:(PGPKey*)pubKey {
    PGPMessageBuilder* builder = [[PGPMessageBuilder alloc] init];
    PGPKey* keyToEncrypt;
    if ([[pubKey subKeys] count] > 0) {
        keyToEncrypt = [[pubKey subKeys] objectAtIndex:0];
    } else {
        keyToEncrypt = pubKey;
    }
    PGPPacketParser* parser = [[PGPPacketParser alloc] init];
    NSData* keyData = [parser getPEMFromPublicKeyPacket:(PGPPublicKeyPacket*)[keyToEncrypt keyData]];
    return [builder buildPGPEncryptedMessageFromData:data withPGPPublicKey:keyData andPubKeyID:(unsigned char*)[[keyToEncrypt keyID] bytes]];
}

@end
