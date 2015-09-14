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

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    NSURL* fileUrl = [[NSBundle mainBundle] URLForResource:@"base64DecodedData" withExtension:@"txt"];
    
    NSData* contentOfURL = [NSData dataWithContentsOfURL:fileUrl];
    //const char *decodedData = [contentOfURL ];
 
    char* decodedData = (char*) contentOfURL.bytes;
    
    [PGPArmorHelper extractPacketsFromBytes:(char*)decodedData andWithPostion:0];
    
    PGPPacket *packet = [[[PGPPacketHelper sharedManager] packets] objectAtIndex:0];

    [PGPArmorHelper extractPublicKeyFromPacket:packet];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
