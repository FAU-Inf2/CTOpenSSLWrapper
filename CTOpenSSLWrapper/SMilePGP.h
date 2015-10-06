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

- (PGPKey*)importPGPKeyFromArmouredFile:(NSData*)fileContent;
- (NSString*)getKeyIDFromArmoredPGPMessage:(NSData*)messageData;
- (NSData*)decryptPGPMessageWithKey:(PGPKey*)secKey fromArmouredFile:(NSData*)fileContent;
- (NSData*)decryptPGPMessageWithKey:(PGPKey*)secKey fromArmouredFile:(NSData*)fileContent WithPassphrase:(NSString*)passphrase;
- (NSData*)buildPGPMessageFromData:(NSData*)data WithKey:(PGPKey*)pubKey;

@end
