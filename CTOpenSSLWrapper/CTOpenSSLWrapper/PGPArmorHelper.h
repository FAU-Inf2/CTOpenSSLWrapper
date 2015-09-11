//
//  PGPArmorHelper.h
//  CTOpenSSLWrapper
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPArmorHelper : NSObject

+ (char *)removeArmorFromKeyFile:(NSURL*)fileUrl;
+ (char *)removeArmorFromKeyFileString:(NSString*)fileContent;

@end
