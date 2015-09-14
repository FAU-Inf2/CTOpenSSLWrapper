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
    int pos = 0;
    int tag;
    int format = 0; //0 = old format; 1 = new format
    int packet_length_type;
    int packet_length;
    int packet_header = bytes[pos++];
    
    //Check format
    if ((packet_header & 0x40) != 0){ //RFC 4.2. Bit 6 -- New packet format if set
        format = 1;
    }
    
    //Get tag
    if (format) {
        //new format
        tag = packet_header & 0x3F; //RFC 4.2. Bits 5-0 -- packet tag
    }else {
        //old format
        tag = (packet_header & 0x3CF) >> 2; //RFC 4.2. Bits 5-2 -- packet tag
        packet_length_type = packet_header & 0x03; //RFC 4.2. Bits 1-0 -- length-type
    }
    
    //Get packet length
    if (!format) {
        //RFC 4.2.1. Old Format Packet Lengths
        switch (packet_length_type) {
            case 0:
                //RFC: The packet has a one-octet length.  The header is 2 octets long.
                packet_length = bytes[pos++];
                break;
            case 1:
                //RFC: The packet has a two-octet length.  The header is 3 octets long.
                packet_length = (bytes[pos++] << 8);
                packet_length = packet_length | bytes[pos++];
                break;
            case 2:
                //RFC: The packet has a four-octet length.  The header is 5 octets long.
                packet_length = (bytes[pos++] << 24);
                packet_length = packet_length | (bytes[pos++] << 16);
                packet_length = packet_length | (bytes[pos++] << 8);
                packet_length = packet_length | bytes[pos++];
                break;
            case 3:
                //TODO
            default:
                break;
        }
    }else {
        //RFC 4.2.2. New Format Packet Lengths
        int first_octet = bytes[pos++];
        
        if(first_octet < 192) {
            //RFC 4.2.2.1. One-Octet Lengths
            packet_length = first_octet;
        } else if (first_octet < 234) {
            //RFC 4.2.2.2. Two-Octet Lengths
            packet_length = ((first_octet - 192) << 8) + (bytes[pos++]) + 192;
        } else if (first_octet == 255) {
            //RFC 4.2.2.3. Five-Octet Lengths
            packet_length = (bytes[pos++] << 24);
            packet_length = packet_length | (bytes[pos++] << 16);
            packet_length = packet_length | (bytes[pos++] << 8);
            packet_length = packet_length | bytes[pos++];
        } else {
            //TODO
            /*RFC: When the length of the packet body is not known in advance by the issuer,
            Partial Body Length headers encode a packet of indeterminate length,
            effectively making it a stream.*/
            return;
        }
    }
    
    //Get Packet
    char packet[packet_length];
    for (int i = 0; i < packet_length; i++) {
        packet[i] = bytes[pos++];
    }
    
    if (tag == 6) { //Public-Key Packet
        [self extractPublicKeyFromBytes:packet];
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
