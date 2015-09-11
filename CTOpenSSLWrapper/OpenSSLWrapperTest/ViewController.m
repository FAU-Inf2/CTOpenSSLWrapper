//
//  ViewController.m
//  OpenSSLWrapperTest
//
//  Created by Jan Weiß on 11.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "ViewController.h"
#include <string.h>

#import "CTOpenSSLWrapper.h"

#import "openssl/evp.h"
#import <openssl/rand.h>
#import <openssl/rsa.h>
#import <openssl/engine.h>
#import <openssl/sha.h>
#import <openssl/pem.h>
#import <openssl/bio.h>
#import <openssl/err.h>
#import <openssl/ssl.h>
#import <openssl/md5.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    [self extractPublicKeyFromBytes:(char*) [@"H" UTF8String]];
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
    int pos = 0;
    char version = bytes[pos++];
    NSLog(@"PGP public key version: %d", version);
    
    if (version == 3 || version == 4) {
        //created = util.readDate(bytes.substr(pos, 4));
        pos += 4;
        
        if (version == 3) {
            //this.expirationTimeV3 = util.readNumber(bytes.substr(pos, 2));
            pos += 2;
        }
    }
    
    int algorithm = bytes[pos++];
    NSLog(@"PGP public key algorithm: %d", algorithm);
    
    char* bmpi = bytes + pos;
    int p = 0;
    
    for (int i = 0; i < 2 && p < strlen(bmpi); i++) {
        int len = bmpi[p] + bmpi[p+1];
        NSLog(@"MPI %d len: %d", i, len);
        BIGNUM* mpi = BN_new();
        BN_set_word(mpi, 0);
        for (int j = p+2; j < p+2+len; j++) {
            BN_add_word(mpi, bmpi[j]);
        }
        NSLog(@"MPI %d value: %@", i, mpi);
        p += 2+len;
    }
    
}

@end
