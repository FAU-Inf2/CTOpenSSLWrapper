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
#import "PGPMessageBuilder.h"
#import "Base64Coder.h"

#import "CTOpenSSLWrapper.h"
#import "CTOpenSSLAsymmetricEncryption.h"

#import "NSData+Godzippa.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSURL* fileUrl = [[NSBundle mainBundle] URLForResource:@"2pgpTestMessage" withExtension:@".txt"];
    NSData* decodedData = [PGPArmorHelper removeArmorFromKeyFile:fileUrl];
    
    fileUrl = [[NSBundle mainBundle] URLForResource:@"encSecKey" withExtension:@".asc"];
    NSData* decodedKeyData = [PGPArmorHelper removeArmorFromKeyFile:fileUrl];
    
    int nextpos = 0;
    do {
        nextpos = [PGPPacketParser extractPacketsFromBytes:decodedData atPostion:nextpos];
    } while (nextpos > 0);
    
    nextpos = 0;
    do {
        nextpos = [PGPPacketParser extractPacketsFromBytes:decodedKeyData atPostion:nextpos];
    } while (nextpos > 0);
    
    PGPPublicKeyEncryptedSessionKeyPacket* packet = [[PGPPacketParser getPacketsWithTag:1] objectAtIndex:0];
    NSData* encryptedSessionKey = [[packet mpis] objectAtIndex:0];
    
    PGPSecretKeyPacket* secretKey = [[PGPPacketParser getPacketsWithTag:7] objectAtIndex:0];
    NSData* secretKeyPEM = [PGPPacketParser getPEMFromSecretKeyPacket:secretKey];
    
    NSData* decryptedSessionKey = CTOpenSSLRSADecrypt(secretKeyPEM, encryptedSessionKey);
    
    NSData* sessionKey = [NSData dataWithBytes:decryptedSessionKey.bytes+1 length:decryptedSessionKey.length-3];
    
    NSData* ret = NULL;
    PGPSymmetricEncryptedIntegrityProtectedDataPacket* p = [[PGPPacketParser getPacketsWithTag:18] objectAtIndex:0];
    NSData* encrypted = [p encryptedData];
    CTOpenSSLSymmetricDecryptAES256CFB(sessionKey, encrypted, &ret);
    
    //ret = [NSData dataWithBytes:[ret bytes] + 18 length:[ret length] - 18];
    ret = [p checkPacketFromDecryptedData:ret];
    
    nextpos = 0;
    do {
        nextpos = [PGPPacketParser extractPacketsFromBytes:ret atPostion:nextpos];
    } while (nextpos > 0);
    
    PGPCompressedDataPacket *cp = [[PGPPacketParser getPacketsWithTag:8] objectAtIndex:0];
    
    NSError *error = NULL;
    NSData* plain = [[cp compressedData] dataByGZipDecompressingDataWithWindowSize:32 error:&error];
    if (error != NULL) {
        NSLog(@"%@", error.description);
    }
    
    nextpos = 0;
    do {
        nextpos = [PGPPacketParser extractPacketsFromBytes:plain atPostion:nextpos];
    } while (nextpos > 0);
    
    /*NSURL* fileUrl = [[NSBundle mainBundle] URLForResource:@"publicTestKey" withExtension:@".asc"];
    NSData* decodedKeyData = [PGPArmorHelper removeArmorFromKeyFile:fileUrl];
    
    int nextpos = 0;
    do {
        nextpos = [PGPPacketParser extractPacketsFromBytes:decodedKeyData atPostion:nextpos];
    } while (nextpos > 0);
    
    PGPPublicKeyPacket* packet = [[PGPPacketParser getPacketsWithTag:14] objectAtIndex:0];
    NSData* pubKeyPEM = [PGPPacketParser getPEMFromPublicKeyPacket:packet];
    
    PGPMessageBuilder *builder = [[PGPMessageBuilder alloc] init];
    unsigned char id[8];
    id[0] = 0x43;
    id[1] = 0xbc;
    id[2] = 0x28;
    id[3] = 0x1f;
    id[4] = 0x26;
    id[5] = 0x43;
    id[6] = 0xd8;
    id[7] = 0xaa;
    NSData* pgpmessage = [builder buildPGPEncryptedMessageFromData:[@"Dies haben wir selbst verschluesselt" dataUsingEncoding:NSUTF8StringEncoding] withPGPPublicKey:pubKeyPEM andPubKeyID:id];
    NSData* checksum = [builder getChecksumForPGPMessageData:pgpmessage];
    NSData* armouredMessage = [builder buildArmouredPGPMessageFromMessageData:pgpmessage andChecksum:checksum];*/
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
