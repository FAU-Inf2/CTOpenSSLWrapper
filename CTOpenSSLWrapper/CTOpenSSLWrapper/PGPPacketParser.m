//
//  PGPPacketHelper.m
//  CTOpenSSLWrapper
//
//  Created by Martin on 14.09.15.
//  Copyright (c) 2015 Home. All rights reserved.
//

#import "PGPPacketParser.h"

#import "PEMHelper.h"

#import "CTOpenSSLDigest.h"
#import "CTOpenSSLSymmetricEncryption.h"

#import <openssl/ossl_typ.h>
#import <openssl/bn.h>
#import <openssl/rsa.h>
#import <openssl/pem.h>
#import <openssl/err.h>

@implementation PGPPacketParser

/*+ (id)sharedManager {
    static PGPPacketParser *sharedMyManager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedMyManager = [[self alloc] init];
    });
    return sharedMyManager;
}*/

- (id)init {
    if (self = [super init]) {
        id arrays[20];
        for (int i = 0; i < 20; i++) {
            arrays[i] = [[NSMutableArray alloc] init];
        }
        self.packets = [NSArray arrayWithObjects:arrays count:20];
    }
    return self;
}

- (NSMutableArray*)getPacketsWithTag:(int) tag {
    return [[self packets] objectAtIndex:tag];
}

- (void) addPacketWithTag:(int)tag andFormat:(int)format andData:(NSData *)data {
    PGPPacket *packet = NULL;
    switch (tag) {
        case 1:
            packet = [[PGPPublicKeyEncryptedSessionKeyPacket alloc] initWithBytes:data andWithTag:tag andWithFormat:format];
            if ([self parsePublicKeyEncryptedSessionKeyPacket:(PGPPublicKeyEncryptedSessionKeyPacket*)packet] == -1) {
                // error
                return;
            }
            break;
        case 5: // SecretKeyPacket
        case 7: // SecretSubKeyPacket
            packet = [[PGPSecretKeyPacket alloc] initWithBytes:data andWithTag:tag andWithFormat:format];
            if ([self parseSecretKeyPacket:(PGPSecretKeyPacket*)packet] == -1) {
                // error
                return;
            }
            break;
        case 6:  // PublicKeyPacket
        case 14: // PublicSubKeyPacket
            packet = [[PGPPublicKeyPacket alloc] initWithBytes:data andWithTag:tag andWithFormat:format];
            if ([self parsePublicKeyPacket:(PGPPublicKeyPacket*)packet] == -1) {
                // error
                return;
            }
            break;
        case 8:
            packet = [[PGPCompressedDataPacket alloc] initWithBytes:data andWithTag:tag andWithFormat:format];
            if ([self parseCompressedDataPacket:(PGPCompressedDataPacket*)packet] == -1) {
                // error
                return;
            }
            break;
        case 11:
            packet = [[PGPLiteralDataPacket alloc] initWithBytes:data andWithTag:tag andWithFormat:format];
            if ([self parseLiteralDataPacket:(PGPLiteralDataPacket*)packet] == -1) {
                //error
                return;
            }
            break;
        case 13:
            packet = [[PGPUserIDPacket alloc] initWithBytes:data andWithTag:tag andWithFormat:format];
            if ([self parseUserIDPacket:(PGPUserIDPacket*)packet] == -1) {
                //error
                return;
            }
            break;
        case 18:
            packet = [[PGPSymmetricEncryptedIntegrityProtectedDataPacket alloc] initWithBytes:data andWithTag:tag andWithFormat:format];
            if ([self parseSymmetricEncryptedIntegrityProtectedDataPacket:(PGPSymmetricEncryptedIntegrityProtectedDataPacket*)packet] == -1) {
                // error
                return;
            }
            break;
        default:
            return;
            break;
    }
    [[self.packets objectAtIndex:packet.tag] addObject:packet];
}

- (int)extractPacketsFromBytes:(NSData*)bytes atPostion:(int)position {
    unsigned char* data = (unsigned char*)bytes.bytes;
    
    int pos = position;
    int packet_tag = -1;
    int packet_format = 0; //0 = old format; 1 = new format
    int packet_length_type = -1;
    size_t packet_length = -1;
    int packet_header = data[pos++];
    
    if ((packet_header & 0x80) == 0) {
        return -1;
    }
    
    //Check format
    if ((packet_header & 0x40) != 0){ //RFC 4.2. Bit 6 -- New packet format if set
        packet_format = 1;
    }
    
    //Get tag
    if (packet_format) {
        //new format
        packet_tag = packet_header & 0x3F; //RFC 4.2. Bits 5-0 -- packet tag
    }else {
        //old format
        packet_tag = (packet_header & 0x3C) >> 2; //RFC 4.2. Bits 5-2 -- packet tag
        packet_length_type = packet_header & 0x03; //RFC 4.2. Bits 1-0 -- length-type
    }
    
    //Get packet length
    if (!packet_format) {
        //RFC 4.2.1. Old Format Packet Lengths
        switch (packet_length_type) {
            case 0:
                //RFC: The packet has a one-octet length.  The header is 2 octets long.
                packet_length =  data[pos++];
                break;
            case 1:
                //RFC: The packet has a two-octet length.  The header is 3 octets long.
                packet_length = ( data[pos++] << 8);
                packet_length = packet_length |  data[pos++];
                break;
            case 2:
                //RFC: The packet has a four-octet length.  The header is 5 octets long.
                packet_length = ( data[pos++] << 24);
                packet_length = packet_length | ( data[pos++] << 16);
                packet_length = packet_length | ( data[pos++] << 8);
                packet_length = packet_length |  data[pos++];
                break;
            case 3:
                //TODO
                packet_length = [bytes length] - pos;
                break;
            default:
                return -1;
                break;
        }
    }else {
        //RFC 4.2.2. New Format Packet Lengths
        int first_octet =  data[pos++];
        
        if(first_octet < 192) {
            //RFC 4.2.2.1. One-Octet Lengths
            packet_length = first_octet;
        } else if (first_octet < 224) {
            //RFC 4.2.2.2. Two-Octet Lengths
            packet_length = ((first_octet - 192) << 8) + ( data[pos++]) + 192;
        } else if (first_octet == 255) {
            //RFC 4.2.2.3. Five-Octet Lengths
            packet_length = ( data[pos++] << 24);
            packet_length = packet_length | ( data[pos++] << 16);
            packet_length = packet_length | ( data[pos++] << 8);
            packet_length = packet_length |  data[pos++];
        } else {
            //TODO
            /*RFC: When the length of the packet body is not known in advance by the issuer,
             Partial Body Length headers encode a packet of indeterminate length,
             effectively making it a stream.*/
            return -1;
        }
    }
    
    //Get Packet_bytes
    unsigned char* packet_bytes = data + pos;
    
    [self addPacketWithTag:packet_tag andFormat:packet_format andData:[NSData dataWithBytes:(const void*)packet_bytes length:packet_length]];
    
    if (bytes.length <= pos+packet_length+1){
        return 0; //End of bytes
    }
    
    return pos+packet_length;
}

- (int)parsePublicKeyPacket:(PGPPublicKeyPacket*) packet {
    int pos = 0;
    unsigned char* bytes = (unsigned char*)[packet.bytes bytes];
    packet.version =  bytes[pos++];
    
    if (packet.version == 3 || packet.version == 4) {
        packet.creationTime = bytes[pos] << 24 | bytes[pos+1] << 16 | bytes[pos+2] << 8 | bytes[pos+3];
        pos += 4;
        
        if (packet.version == 3) {
            packet.daysTillExpiration = bytes[pos] << 8 | bytes[pos+1];
            pos += 2;
        }
    } else {
        return -1;
    }
    
    packet.algorithm =  bytes[pos++];
    if (packet.algorithm != 1) {
        return -1;
    }
    
    unsigned char* bmpi = bytes + pos;
    int p = 0;
    int mpiCount = 2; // only rsa supported at the moment
    
    for (int i = 0; i < mpiCount && p < [packet.bytes length]-pos; i++) {
        double len = (bmpi[p] << 8) | bmpi[p+1];
        int byteLen = ceil(len / 8);
        unsigned char mpi[byteLen];
        for (int j = 0; j < byteLen; j++) {
            mpi[j] = bmpi[2+j+p];
        }
        [packet.mpis addObject:[NSData dataWithBytes:(const void*)mpi length:byteLen]];
        p += byteLen+2;
    }
    packet.bytes = [NSData dataWithBytes:[packet.bytes bytes] length:p+pos];
    return p+pos; // bytes read
}

- (int)parseSecretKeyPacket:(PGPSecretKeyPacket *)packet {
    int pos = 0;
    unsigned char* bmpi = NULL;
    int p = 0;
    int mpiCount = 0;
    unsigned char* bytes = (unsigned char*)[packet.bytes bytes];
    NSData* dataToCheck;
    int checksum = 0;
    int checkValue = 0;
    
    //Extract PublicKey from packet
    PGPPublicKeyPacket *pubKey = [[PGPPublicKeyPacket alloc] initWithBytes:packet.bytes andWithTag:packet.tag andWithFormat:packet.format];
    pos = [self parsePublicKeyPacket:pubKey];
    if (pos == -1) {
        return -1;
    }
    packet.pubKey = pubKey;
    
    packet.s2k = bytes[pos++];
    unsigned char saltValue[8];
    int is2k_count = 0;
    
    switch (packet.s2k) {
        case 0:
            // Indicates that the secret-key data is not encrypted
            // Get MPIs
            bmpi = bytes + pos;
            mpiCount = 4; // only rsa supported at the moment
            
            for (int i = 0; i < mpiCount && p < ([packet.bytes length] - pos); i++) {
                double len = bmpi[p] << 8 | bmpi[p+1];
                int byteLen = ceil(len/8);
                
                unsigned char mpi[byteLen];
                for (int j = 0; j < byteLen; j++) {
                    mpi[j] = bmpi[2+j+p];
                }
                [packet.mpis addObject:[NSData dataWithBytes:(const void*)mpi length:byteLen]];
                p += byteLen+2;
            }
            checksum = bmpi[p] << 8 | bmpi[p+1];
            dataToCheck = [NSData dataWithBytes:bmpi length:p];
            for (int i = 0; i < [dataToCheck length]; i++) {
                checkValue += ((unsigned char*)[dataToCheck bytes])[i];
            }
            if ((checkValue % 65536) != (checksum)) {
                return -1;
            }
            packet.encryptedData = NULL;
            return p+pos+2;
            break;
        case 255:
        case 254:
            // Indicates that a string-to-key specifier is being given
            packet.symmetricEncAlgorithm = bytes[pos++];
            packet.s2kSpecifier = bytes[pos++];
            if (packet.s2kSpecifier == 2 || (packet.s2kSpecifier >= 100 && packet.s2kSpecifier <= 110)) {
                return -1;
            }
            packet.s2kHashAlgorithm = bytes[pos++];
            if (packet.s2kSpecifier > 0) {
                for (int i = 0; i < 8; i++) {
                    saltValue[i] = bytes[pos++];
                }
                packet.s2kSaltValue = [NSData dataWithBytes:(const void *)saltValue length:8];
                if (packet.s2kSpecifier == 3) {
                    packet.s2kCount = bytes[pos++];
                } else {
                    packet.s2kCount = 0;
                }
            }
            break;
        default:
            // Any other value is a symmetric-key encryption algorithm identifier
            packet.symmetricEncAlgorithm = packet.s2k;
            break;
    }
    
    int blockSize = 0;
    switch (packet.symmetricEncAlgorithm) {
        case 3:
            blockSize = 8;
            break;
        case 9:
            blockSize = 16;
            break;
        default: //All other values are not supported yet
            return -1;
            break;
    }
    unsigned char iv[blockSize];
    for (int i = 0; i < blockSize; i++) {
        iv[i] = bytes[pos++];
    }
    packet.initialVector = [NSData dataWithBytes:(const void *)iv length:blockSize];
    packet.encryptedData = [NSData dataWithBytes:(const void *)bytes+pos length:[packet.bytes length]-pos];
    
    return [packet.bytes length]; // bytes read
}

- (int)parsePublicKeyEncryptedSessionKeyPacket:(PGPPublicKeyEncryptedSessionKeyPacket *)packet {
    int pos = 0;
    unsigned char* bytes = (unsigned char*)[packet.bytes bytes];
    packet.version = bytes[pos++];
    packet.pubKeyID = calloc(8, sizeof(char));
    for (int i = 0; i < 8; i++) {
        packet.pubKeyID[i] = bytes[pos++];
    }

    packet.algorithm = bytes[pos++];
    
    // Get MPI
    unsigned char* bmpi = bytes + pos;
    
    double len = bmpi[0] << 8 | bmpi[1];
    int byteLen = ceil(len/8);
    
    unsigned char mpi[byteLen];
    for (int j = 0; j < byteLen; j++) {
        mpi[j] = bmpi[j+2];
    }
    [packet.mpis addObject:[NSData dataWithBytes:(const void*)mpi length:byteLen]];
    
    return pos+byteLen+2; // bytes read
}

- (int)parseSymmetricEncryptedIntegrityProtectedDataPacket:(PGPSymmetricEncryptedIntegrityProtectedDataPacket *)packet{
    int pos = 0;
    unsigned char* bytes = (unsigned char*)[packet.bytes bytes];
    packet.version = bytes[pos++]; //RFC: A one-octet version number.  The only currently defined value is 1.
    
    if (packet.version != 1) {
        return -1;
    }
    
    //Encrypted data, the output of the selected symmetric-key cipher operating in Cipher Feedback mode with shift amount equal to the block size of the cipher (CFB-n where n is the block size)
    unsigned char data[[packet.bytes length]-pos];
    for (int i = 0; i < [packet.bytes length]-pos; i++) {
        data[i] = bytes[i+pos];
    }
    packet.encryptedData = [NSData dataWithBytes:data length:[packet.bytes length]-pos];
    
    return [packet.bytes length];
}

- (int)parseCompressedDataPacket:(PGPCompressedDataPacket *)packet {
    int pos = 0;
    unsigned char* bytes = (unsigned char*)[packet.bytes bytes];
    
    packet.algorithm = bytes[pos++];
    
    packet.compressedData = [NSData dataWithBytes:(const void*)bytes+pos length:[packet.bytes length]-pos];
    
    return [packet.bytes length];
}

- (int)parseLiteralDataPacket:(PGPLiteralDataPacket *)packet {
    int pos = 0;
    unsigned char* bytes = (unsigned char*)[packet.bytes bytes];
    
    packet.formatType = bytes[pos++];
    
    int strLen = bytes[pos++];
    if (strLen == 0) {
        packet.fileName = @"";
    } else {
        char str[strLen];
        for (int i = 0; i < strLen; i++) {
            str[i] = bytes[pos+i];
        }
    }
    pos += strLen;
    
    packet.date = bytes[pos] << 24 | bytes[pos+1] << 16 | bytes[pos+2] << 8 | bytes[pos+3];
    pos += 4;
    
    packet.literalData = [NSData dataWithBytes:(const void *) bytes+pos length:[packet.bytes length]-pos];
    
    return [packet.bytes length];
}

- (int)parseUserIDPacket:(PGPUserIDPacket *)packet {
    packet.userID = [[NSString alloc] initWithData:packet.bytes encoding:NSUTF8StringEncoding];
    return [packet.bytes length];
}

- (NSData*) getPEMFromSecretKeyPacket:(PGPSecretKeyPacket *)packet {
    RSA* privateRSA = RSA_new();
    
    NSData* n = [[[packet pubKey] mpis] objectAtIndex:0];
    privateRSA->n = BN_bin2bn((const unsigned char*) [n bytes], [n length], NULL);
    
    NSData* e = [[[packet pubKey] mpis] objectAtIndex:1];
    privateRSA->e = BN_bin2bn((const unsigned char*) [e bytes], [e length], NULL);
    
    NSData* d = [[packet mpis] objectAtIndex:0];
    privateRSA->d = BN_bin2bn((const unsigned char*) [d bytes], [d length], NULL);
    
    NSData* p = [[packet mpis] objectAtIndex:1];
    privateRSA->p = BN_bin2bn((const unsigned char*) [p bytes], [p length], NULL);
    
    NSData* q = [[packet mpis] objectAtIndex:2];
    privateRSA->q = BN_bin2bn((const unsigned char*) [q bytes], [q length], NULL);
    
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* m = BN_new();
    
    privateRSA->dmp1 = BN_new();
    BN_sub(m, privateRSA->p, BN_value_one());
    BN_mod(privateRSA->dmp1, privateRSA->d, m, ctx);
    
    privateRSA->dmq1 = BN_new();
    BN_sub(m, privateRSA->q, BN_value_one());
    BN_mod(privateRSA->dmq1, privateRSA->d, m, ctx);
    
    privateRSA->iqmp = BN_mod_inverse(NULL, privateRSA->q, privateRSA->p, ctx);
    
    return [PEMHelper writeKeyToPEMWithRSA:privateRSA andIsPrivate:YES];
}

- (NSData*) getPEMFromPublicKeyPacket:(PGPPublicKeyPacket *)packet {
    RSA* publicRSA = RSA_new();
    
    NSData* n = [[packet mpis] objectAtIndex:0];
    publicRSA->n = BN_bin2bn((const unsigned char*) [n bytes], [n length], NULL);
    
    NSData* e = [[packet mpis] objectAtIndex:1];
    publicRSA->e = BN_bin2bn((const unsigned char*) [e bytes], [e length], NULL);
    
    publicRSA->d = NULL;
    
    publicRSA->p = NULL;
    
    publicRSA->q = NULL;
    
    publicRSA->dmp1 = NULL;
    
    publicRSA->dmq1 = NULL;
    
    publicRSA->iqmp = NULL;
    
    return [PEMHelper writeKeyToPEMWithRSA:publicRSA andIsPrivate:NO];
}

- (NSData*)generateKeyID:(PGPPublicKeyPacket *)packet {
    NSData* keyID;
    if (packet.version == 4) {
        int pos = 0;
        unsigned char bytesToHash[3+[packet.bytes length]];
        bytesToHash[pos++] = '\x99';
        bytesToHash[pos++] = (unsigned char)([packet.bytes length] >> 8);
        bytesToHash[pos++] = (unsigned char)[packet.bytes length];
        for (int i = 0; i < [packet.bytes length]; i++) {
            bytesToHash[pos++] = ((unsigned char*)[packet.bytes bytes])[i];
        }
        NSData* dataToHash = [NSData dataWithBytes:(const void *)bytesToHash length:pos];
        NSData* fingerprint = CTOpenSSLGenerateDigestFromData(dataToHash, CTOpenSSLDigestTypeSHA1);
        keyID = [NSData dataWithBytes:[fingerprint bytes]+([fingerprint length]-8) length:8];
    } else {
        NSData* publicModulus = [[packet mpis] objectAtIndex:0];
        keyID = [NSData dataWithBytes:[publicModulus bytes]+([publicModulus length]-8) length:8];
    }
    return keyID;
}

@end
