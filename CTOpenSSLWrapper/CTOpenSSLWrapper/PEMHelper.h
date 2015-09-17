//
//  PEMHelper.h
//  CTOpenSSLWrapper
//
//  Created by Moritz Müller on 17.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <openssl/ossl_typ.h>

@interface PEMHelper : NSObject

+ (NSData*)writeKeyToPEMWithRSA:(RSA*) rsa andIsPrivate:(BOOL) isPrivate;
+ (RSA*)readPUBKEYFromPEMdata:(NSData*) data;

@end
