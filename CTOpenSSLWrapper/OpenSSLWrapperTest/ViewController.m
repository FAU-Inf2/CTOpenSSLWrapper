//
//  ViewController.m
//  OpenSSLWrapperTest
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void)extractPacketsFromBytes:(char *)bytes {
    int tag = bytes[0];
    int first_octet = bytes[1];
    int second_octet = bytes[2];
    int third_octet = bytes[3];
    int fourth_octet = bytes[4];
    int fiveth_octet = bytes[5];
    int bodyLen = 0;
    
    if (tag == 0xC6) { //Tag 6 == Public Key Packet
        NSLog(@"Tag == 6");
        if (first_octet < 192) {
            //Fill Body
            bodyLen = first_octet;
            NSLog(@"bodyLen = %d", bodyLen);
            char body[bodyLen];
            for (int i = 0; i < bodyLen; i++) {
                body[i] = bytes[i+2];
            }
            [self extractPublicKeyFromBytes:body];
            
        }else if (first_octet < 234) {
            //Fill Body
            bodyLen = ((first_octet - 192) << 8) + (second_octet) + 192;
            NSLog(@"bodyLen = %d", bodyLen);
            char body[bodyLen];
            for (int i = 0; i < bodyLen; i++) {
                body[i] = bytes[i+3];
            }
            [self extractPublicKeyFromBytes:body];
            
        }else if (first_octet == 255) {
            //Fill Body
            bodyLen = (second_octet << 24) | (third_octet << 16) | (fourth_octet << 8)  | fiveth_octet;
            NSLog(@"bodyLen = %d", bodyLen);
            char body[bodyLen];
            for (int i = 0; i < bodyLen; i++) {
                body[i] = bytes[i+6];
            }
            [self extractPublicKeyFromBytes:body];
            
        }else {
            //Exception
            return;
        }
    }
}

- (void)extractPublicKeyFromBytes:(char *)bytes {
    
}

@end
