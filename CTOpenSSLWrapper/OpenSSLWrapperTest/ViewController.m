//
//  ViewController.m
//  OpenSSLWrapperTest
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "ViewController.h"
#import "PGPArmorHelper.h"
#import "PGPPacketHelper.h"

#import "CTOpenSSLWrapper.h"
#import "CTOpenSSLAsymmetricEncryption.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSURL* fileUrl = [[NSBundle mainBundle] URLForResource:@"pgpTestMessage" withExtension:@".txt"];
    NSData* decodedData = [PGPArmorHelper removeArmorFromKeyFile:fileUrl];
    
    int nextpos = 0;
    do {
        nextpos = [PGPArmorHelper extractPacketsFromBytes:(unsigned char*) decodedData.bytes withLength:decodedData.length andWithPostion:nextpos];
    } while (nextpos > 0);
    
    PGPPacket* packet = [[[PGPPacketHelper sharedManager] packets] objectAtIndex:0];
    
    NSData* symmetricKeyEnc = [PGPArmorHelper extractEncryptedSymmetricSessionKeyFromPacket:packet];
    
    fileUrl = [[NSBundle mainBundle] URLForResource:@"privateTestKey" withExtension:@".asc"];
    decodedData = [PGPArmorHelper removeArmorFromKeyFile:fileUrl];
    
    nextpos = 0;
    do {
        nextpos = [PGPArmorHelper extractPacketsFromBytes:(unsigned char*) decodedData.bytes withLength:decodedData.length andWithPostion:nextpos];
    } while (nextpos > 0);
    
    NSData* secretKey = NULL;
    for (int i = 0; i < [[[PGPPacketHelper sharedManager] packets] count]; i++) {
        PGPPacket* tmp = [[[PGPPacketHelper sharedManager] packets] objectAtIndex:i];
        if ([tmp tag] == 5) {
            secretKey = [PGPArmorHelper extractPrivateKeyFromPacket:tmp];
        }
    }
    
    NSData* symmetricKeyDec = CTOpenSSLRSADecryptWithPadding(secretKey, symmetricKeyEnc, 3);//CTOpenSSLRSADecrypt(secretKey, symmetricKeyEnc);
    
    /*PGPPacket *packet = [[[PGPPacketHelper sharedManager] packets] objectAtIndex:0];
    
    NSData* pubKey = [PGPArmorHelper extractPublicKeyFromPacket:packet pos:NULL];
    NSData* secKey = [PGPArmorHelper extractPrivateKeyFromPacket:packet];
     
    NSData* shitbull = CTOpenSSLRSAEncrypt(pubKey, [@"bullshit encoded" dataUsingEncoding:NSUTF8StringEncoding]);
     
    NSLog(@"Shitbull: %@", [[NSString alloc] initWithData:shitbull encoding:NSUTF8StringEncoding]);
    
    NSData* bullshit = CTOpenSSLRSADecrypt(secKey, shitbull);
    
    NSLog(@"Bullshit: %@", [[NSString alloc] initWithData:bullshit encoding:NSUTF8StringEncoding]);*/
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
