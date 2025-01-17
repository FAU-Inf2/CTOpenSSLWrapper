//
//  CTOpenSSLSymmetricEncryption.h
//  CTOpenSSLWrapper
//
//  Created by Oliver Letterer on 05.06.12.
//  Copyright 2012 Home. All rights reserved.
//

NS_ASSUME_NONNULL_BEGIN

typedef enum {
    CTOpenSSLCipherAES256 = 0,
    CTOpenSSLCipherAES128CFB = 1,
    CTOpenSSLCipherAES192CFB = 2,
    CTOpenSSLCipherAES256CFB = 3,
    CTOpenSSLCipherCAST5CFB = 4
} CTOpenSSLCipher;

NSString *NSStringFromCTOpenSSLCipher(CTOpenSSLCipher cipher);

/**
 @abstract  encrypts data symmetrically
 @param     cipher: the cipher to be used
 @param     symmetricKeyData: data which will be used as symmetric key
 @param     data: data to be encrypted
 @return    encrypted data
 */
BOOL CTOpenSSLSymmetricEncrypt(CTOpenSSLCipher cipher, NSData *symmetricKeyData, NSData *data, NSData *__nullable *__nonnull encryptedData);

/**
 @abstract  decrypts data symmetrically
 @param     cipher: the cipher to be used
 @param     symmetricKeyData: data which will be used as symmetric key
 @param     encryptedData: data to be decrypted
 @return    decrypted data
 */
BOOL CTOpenSSLSymmetricDecrypt(CTOpenSSLCipher cipher, NSData *symmetricKeyData, NSData *encryptedData, NSData *__nullable *__nonnull decryptedData);

BOOL CTOpenSSLSymmetricEncryptAES256CFB(NSData *symmetricKeyData, NSData *data, NSData *__nullable *__nonnull encryptedData);
BOOL CTOpenSSLSymmetricDecryptAES256CFB(NSData *symmetricKeyData, NSData *encryptedData, NSData *__nullable *__nonnull decryptedData);
BOOL CTOpenSSLSymmetricDecryptWithIV(CTOpenSSLCipher CTCipher, NSData* initialVector, NSData *symmetricKeyData, NSData *encryptedData, NSData *__nullable *__nonnull decryptedData);

NS_ASSUME_NONNULL_END
