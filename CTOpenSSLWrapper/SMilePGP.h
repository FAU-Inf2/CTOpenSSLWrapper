//
//  SMilePGP.h
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 05.10.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "PGPKey.h"

@interface SMilePGP : NSObject

- (nullable PGPKey*)importPGPKeyFromArmouredFile:(nonnull NSData*)fileContent;
- (nullable NSString*)getKeyIDFromArmoredPGPMessage:(nonnull NSData*)messageData;
- (nullable NSData*)decryptPGPMessageWithKey:(nonnull PGPKey*)secKey fromArmouredFile:(nonnull NSData*)fileContent;
- (nullable NSData*)decryptPGPMessageWithKey:(nonnull PGPKey*)secKey fromArmouredFile:(nonnull NSData*)fileContent WithPassphrase:(nullable NSString*)passphrase;
- (nullable NSData*)buildPGPMessageFromData:(nonnull NSData* )data WithKey:(nonnull PGPKey*)key;

@end
