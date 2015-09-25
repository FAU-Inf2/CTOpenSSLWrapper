//
//  ViewController.m
//  OpenSSLWrapperTest
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "ViewController.h"
#import "PGPArmorHelper.h"
#import "PGPPacketParser.h"

#import "CTOpenSSLWrapper.h"
#import "CTOpenSSLAsymmetricEncryption.h"

#import "PGPPublicKeyEncryptedSessionKeyPacket.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import "PGPSymmetricEncryptedIntegrityProtectedDataPacket.h"
#import "PGPCompressedDataPacket.h"

#import "NSData+Godzippa.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSURL* fileUrl = [[NSBundle mainBundle] URLForResource:@"pgpTestMessage" withExtension:@".txt"];
    //NSData* decodedData = [PGPArmorHelper removeArmorFromKeyFile:fileUrl];
    
    fileUrl = [[NSBundle mainBundle] URLForResource:@"privateTestKey" withExtension:@".asc"];
    NSData* decodedKeyData = [PGPArmorHelper removeArmorFromKeyFile:fileUrl];
    
    fileUrl = [[NSBundle mainBundle] URLForResource:@"outbase64" withExtension:@".txt"];
    NSData* decodedData = [[NSData alloc] initWithContentsOfURL:fileUrl];
    
    int nextpos = 0;
    do {
        nextpos = [PGPPacketParser extractPacketsFromBytes:decodedData atPostion:nextpos];
    } while (nextpos > 0);
    
    nextpos = 0;
    do {
        nextpos = [PGPPacketParser extractPacketsFromBytes:decodedKeyData atPostion:nextpos];
    } while (nextpos > 0);
    
    PGPPublicKeyEncryptedSessionKeyPacket* packet = [[[[PGPPacketParser sharedManager] packets] objectAtIndex:1] objectAtIndex:0];
    NSData* encryptedSessionKey = [[packet mpis] objectAtIndex:0];
    
    PGPSecretKeyPacket* secretKey = [[[[PGPPacketParser sharedManager] packets] objectAtIndex:7] objectAtIndex:0];
    NSData* secretKeyPEM = [PGPPacketParser getPEMFromSecretKeyPacket:secretKey];
    
    NSData* decryptedSessionKey = CTOpenSSLRSADecrypt(secretKeyPEM, encryptedSessionKey);
    
    NSData* sessionKey = [NSData dataWithBytes:decryptedSessionKey.bytes+1 length:decryptedSessionKey.length-3];
    
    NSData* ret = NULL;
    PGPSymmetricEncryptedIntegrityProtectedDataPacket* p = [[[[PGPPacketParser sharedManager] packets] objectAtIndex:18] objectAtIndex:0];
    NSData* encrypted = [[[[[PGPPacketParser sharedManager] packets] objectAtIndex:18] objectAtIndex:0] encryptedData];
    NSLog(@"%i", [[p bytes] length]);
    CTOpenSSLSymmetricDecryptAES256CFB(sessionKey, encrypted, &ret);
    
    //ret = [NSData dataWithBytes:[ret bytes] + 18 length:[ret length] - 18];
    ret = [p checkPacketFromDecryptedData:ret];
    
    nextpos = 0;
    do {
        nextpos = [PGPPacketParser extractPacketsFromBytes:ret atPostion:nextpos];
    } while (nextpos > 0);
    
    PGPCompressedDataPacket *cp = [[[[PGPPacketParser sharedManager] packets] objectAtIndex:8] objectAtIndex:0];
    
    NSError *error = NULL;
    NSData* plain = [[cp compressedData] dataByGZipDecompressingDataWithWindowSize:32 error:&error];
    if (error != NULL) {
        NSLog(@"%@", error.description);
    }
    
    nextpos = 0;
    do {
        nextpos = [PGPPacketParser extractPacketsFromBytes:plain atPostion:nextpos];
    } while (nextpos > 0);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
