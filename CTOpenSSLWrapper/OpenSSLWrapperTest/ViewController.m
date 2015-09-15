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
    
    /*NSData* privKey = CTOpenSSLGeneratePrivateRSAKey(2048, CTOpenSSLPrivateKeyFormatPEM);
    
    NSData* pubKey = CTOpenSSLExtractPublicKeyFromPrivateRSAKey(privKey);*/
    
    NSURL* fileUrl = [[NSBundle mainBundle] URLForResource:@"base64DecodedData" withExtension:@"txt"];
    
    NSData* contentOfURL = [NSData dataWithContentsOfURL:fileUrl];
    //const char *decodedData = [contentOfURL ];
 
    char* decodedData = (char*) contentOfURL.bytes;
    
    [PGPArmorHelper extractPacketsFromBytes:(char*)decodedData andWithPostion:0];
    
    PGPPacket *packet = [[[PGPPacketHelper sharedManager] packets] objectAtIndex:0];

    NSData* data = [PGPArmorHelper extractPublicKeyFromPacket:packet];
    
    NSData* shitbull = CTOpenSSLRSAEncrypt(data, [@"bullshit encoded" dataUsingEncoding:NSUTF8StringEncoding]);
    
    NSLog(@"Shitbull: %@", [[NSString alloc] initWithData:shitbull encoding:NSUTF8StringEncoding]);
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
