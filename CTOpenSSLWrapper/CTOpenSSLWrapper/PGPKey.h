//
//  PGPKey.h
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 05.10.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

@interface PGPKey : NSObject

@property (nonatomic) NSData* keyID;
@property (nonatomic) NSData* fingerprint;
@property (nonatomic) NSMutableArray* userIDs;
@property (nonatomic) int keyLength;
@property (nonatomic) PGPPacket* keyData;
@property (nonatomic) NSMutableArray* subKeys;
@property (nonatomic) BOOL encryted;
@property (nonatomic) BOOL isPrivate;

- (id)initWithKeyID:(NSData*)keyID andWithFingerPrint:(NSData*)fingerprint andWithUserIDs:(NSMutableArray*)userIDs andWithKeyLength:(int)keyLength andWithKeyData:(PGPPacket*)keyData andIsPrivate:(BOOL)isPrivate andIsEncrypted:(BOOL)encrypted;

- (NSString*)getKeyID;
- (NSString*)getFingerPrint;
- (NSMutableArray*)getUserIDs;
- (int)getKeyLength;
- (int)getKeyVersion;
- (NSDate*)getCreationDate;
- (int)getTimeInDaysTillExpiration;
- (int)getKeyAlgorithm;

- (NSData*)decryptKeyWithPassphrase:(NSString*)passphrase;
- (NSData*)generateSymmKeyFromPassphrase:(NSString*)passphrase withSaltSpecifier:(int)s2k andHashalgorithm:(int)algorithm andSaltValue:(NSData*)salt andSaltCount:(int)count andKeyLen:(int)keyLen;

@end
