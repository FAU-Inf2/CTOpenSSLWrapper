//
//  PGPKey.m
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 05.10.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPKey.h"

#import "PGPSecretKeyPacket.h"
#import "PGPPublicKeyPacket.h"

#import "CTOpenSSLDigest.h"
#import "CTOpenSSLSymmetricEncryption.h"
#import "PGPPacketParser.h"

@implementation PGPKey

- (id)initWithKeyID:(NSData *)keyID andWithFingerPrint:(NSData*)fingerprint andWithUserIDs:(NSMutableArray*)userIDs andWithKeyLength:(int)keyLength andWithKeyData:(PGPPacket *)keyData andIsPrivate:(BOOL)isPrivate andIsEncrypted:(BOOL)encrypted {
    if (self = [super init]) {
        self.keyID = keyID;
        self.fingerprint = fingerprint;
        self.userIDs = userIDs;
        self.keyLength = keyLength;
        self.keyData = keyData;
        self.isPrivate = isPrivate;
        self.encryted = encrypted;
        self.subKeys = [[NSMutableArray alloc] init];
    }
    return self;
}

- (NSString*)getKeyID {
    NSString* keyid = [[self.keyID description] uppercaseString];
    keyid = [keyid substringFromIndex:1];
    keyid = [keyid substringToIndex:[keyid length]-1];
    return keyid;
}

- (NSString*)getFingerPrint {
    NSString* fingerprint = [[self.fingerprint description] uppercaseString];
    fingerprint = [fingerprint substringFromIndex:1];
    fingerprint = [fingerprint substringToIndex:[fingerprint length]-1];
    return fingerprint;
}

- (NSMutableArray*)getUserIDs {
    return self.userIDs;
}

- (int)getKeyLength {
    return self.keyLength;
}

- (int)getKeyVersion {
    if (self.isPrivate) {
        return [[(PGPSecretKeyPacket*)self.keyData pubKey] version];
    } else {
        return [(PGPPublicKeyPacket*)self.keyData version];
    }
}

- (NSDate*)getCreationDate {
    if (self.isPrivate) {
        return [NSDate dateWithTimeIntervalSince1970:[[(PGPSecretKeyPacket*)self.keyData pubKey] creationTime]];
    } else {
        return [NSDate dateWithTimeIntervalSince1970:[(PGPPublicKeyPacket*)self.keyData creationTime]];
    }
}

- (int)getTimeInDaysTillExpiration {
    if (self.isPrivate) {
        return [[(PGPSecretKeyPacket*)self.keyData pubKey] daysTillExpiration];
    } else {
        return [(PGPPublicKeyPacket*)self.keyData daysTillExpiration];
    }
}

- (int)getKeyAlgorithm {
    if (self.isPrivate) {
        return [[(PGPSecretKeyPacket*)self.keyData pubKey] algorithm];
    } else {
        return [(PGPPublicKeyPacket*)self.keyData algorithm];
    }
}

- (NSData*)decryptKeyWithPassphrase:(NSString*)passphrase {
    // Generate symm. key
    if (!self.isPrivate && !self.encryted) {
        return NULL;
    }
    PGPSecretKeyPacket* packet = (PGPSecretKeyPacket*)self.keyData;
    int keyLen = 0;
    switch (packet.symmetricEncAlgorithm) {
        case 3:
            keyLen = 16;
            break;
        case 9:
            keyLen = 32;
            break;
        default: //All other values are not supported yet
            return NULL;
            break;
    }
    
    NSData* symKey = [self generateSymmKeyFromPassphrase:passphrase withSaltSpecifier:packet.s2kSpecifier andHashalgorithm:packet.s2kHashAlgorithm andSaltValue:packet.s2kSaltValue andSaltCount:packet.s2kCount andKeyLen:keyLen];
    
    NSData* mpis = NULL;
    CTOpenSSLSymmetricDecryptWithIV(CTOpenSSLCipherCAST5CFB, packet.initialVector, symKey, packet.encryptedData, &mpis);
    
    // parse mpis
    PGPSecretKeyPacket* tmp = [[PGPSecretKeyPacket alloc] initWithBytes:packet.bytes andWithTag:packet.tag andWithFormat:packet.format];
    tmp.pubKey = packet.pubKey;
    unsigned char* bmpi = (unsigned char*)[mpis bytes];
    int mpiCount = 4; // only rsa supported at the moment
    int p = 0;
    
    for (int i = 0; i < mpiCount && p < [mpis length]; i++) {
        double len = bmpi[p] << 8 | bmpi[p+1];
        int byteLen = ceil(len/8);
        
        unsigned char mpi[byteLen];
        for (int j = 0; j < byteLen; j++) {
            mpi[j] = bmpi[2+j+p];
        }
        [tmp.mpis addObject:[NSData dataWithBytes:(const void*)mpi length:byteLen]];
        
        p += byteLen+2;
    }
    
    // Check Hash
    NSData* dataToCheck;
    int checksum = 0;
    int checkValue = 0;
    if (packet.s2k != 254) {
        checksum = ((unsigned char*)[mpis bytes])[[mpis length]-2] << 8 | ((unsigned char*)[mpis bytes])[[mpis length]-1];
        dataToCheck = [NSData dataWithBytes:[mpis bytes] length:[mpis length]-2];
        for (int i = 0; i < [dataToCheck length]; i++) {
            checkValue += ((unsigned char*)[dataToCheck bytes])[i];
        }
        if ((checkValue % 65536) != (checksum)) {
            return NULL;
        }
    } else {
        dataToCheck = [NSData dataWithBytes:[mpis bytes] length:[mpis length]-20];
        dataToCheck = CTOpenSSLGenerateDigestFromData(dataToCheck, CTOpenSSLDigestTypeSHA1);
        for (int i = 0; i < 20; i++) {
            if (((unsigned char*)[dataToCheck bytes])[i] != ((unsigned char*)[mpis bytes])[([mpis length] - 20)+i]) {
                return NULL;
            }
        }
    }
    
    PGPPacketParser* parser = [[PGPPacketParser alloc] init];
    return [parser getPEMFromSecretKeyPacket:tmp];
}

- (NSData*)generateSymmKeyFromPassphrase:(NSString*)passphrase withSaltSpecifier:(int)s2k andHashalgorithm:(int)algorithm andSaltValue:(NSData*)salt andSaltCount:(int)count andKeyLen:(int)keyLen {
    CTOpenSSLDigestType hash;
    switch (algorithm) {
        case 0:
            break;
        case 1:
            hash = CTOpenSSLDigestTypeMD5;
            break;
        case 2:
            hash = CTOpenSSLDigestTypeSHA1;
            break;
        case 8:
            hash = CTOpenSSLDigestTypeSHA256;
            break;
        case 10:
            hash = CTOpenSSLDigestTypeSHA512;
            break;
        default:
            return NULL;
            break;
    }
    NSMutableData* ret = [[NSMutableData alloc] initWithLength:0];
    NSMutableData* prefix = [[NSMutableData alloc] initWithLength:0];
    
    while ([ret length] <= keyLen) {
        
        NSMutableData* dataToHash = [[NSMutableData alloc] init];
        NSMutableData* isp = [prefix mutableCopy];
        unsigned int octetsToHash = 0;
        switch (s2k) {
            case 1:
                [dataToHash appendData:salt];
            case 0:
                [dataToHash appendData:[passphrase dataUsingEncoding:NSUTF8StringEncoding]];
                break;
            case 3:
                octetsToHash = (16 + (count & 15)) << ((count >> 4) + 6);
                [dataToHash appendData:salt];
                [dataToHash appendData:[passphrase dataUsingEncoding:NSUTF8StringEncoding]];
                while ([isp length] < octetsToHash) {
                    [isp appendData:dataToHash];
                }
                if ([isp length] > octetsToHash) {
                    dataToHash = [[NSData dataWithBytes:[isp bytes] length:octetsToHash] mutableCopy];
                } else {
                    dataToHash = isp;
                }
                break;
            default:
                [dataToHash appendData:[passphrase dataUsingEncoding:NSUTF8StringEncoding]];
                hash = CTOpenSSLDigestTypeMD5;
                break;
        }
        
        [ret appendData: CTOpenSSLGenerateDigestFromData(dataToHash, hash)];
        [prefix appendBytes:(const void *)"\0" length:1];
        
    }
    
    return [NSData dataWithBytes:[ret bytes] length:keyLen];
}

@end
