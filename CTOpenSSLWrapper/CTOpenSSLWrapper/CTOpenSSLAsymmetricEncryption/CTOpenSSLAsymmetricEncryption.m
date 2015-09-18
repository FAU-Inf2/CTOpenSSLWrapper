//
//  CTOpenSSLAsymmetricEncryption.m
//  CTOpenSSLWrapper
//
//  Created by Oliver Letterer on 05.06.12.
//  Copyright 2012 Home. All rights reserved.
//

#import "CTOpenSSLWrapper.h"

#import <openssl/evp.h>
#import <openssl/rand.h>
#import <openssl/rsa.h>
#import <openssl/engine.h>
#import <openssl/sha.h>
#import <openssl/pem.h>
#import <openssl/bio.h>
#import <openssl/err.h>
#import <openssl/ssl.h>
#import <openssl/md5.h>

static int RSA_eay_private_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, RSA *rsa, int padding)
{
    BIGNUM *f, *ret;
    int j, num = 0, r = -1;
    unsigned char *p;
    unsigned char *buf = NULL;
    BN_CTX *ctx = NULL;
    int local_blinding = 0;
    /*
     * Used only if the blinding structure is shared. A non-NULL unblind
     * instructs rsa_blinding_convert() and rsa_blinding_invert() to store
     * the unblinding factor outside the blinding structure.
     */
    BIGNUM *unblind = NULL;
    BN_BLINDING *blinding = NULL;
    
    if ((ctx = BN_CTX_new()) == NULL)
        goto err;
    BN_CTX_start(ctx);
    f = BN_CTX_get(ctx);
    ret = BN_CTX_get(ctx);
    num = BN_num_bytes(rsa->n);
    buf = OPENSSL_malloc(num);
    if (!f || !ret || !buf) {
        RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    
    /*
     * This check was for equality but PGP does evil things and chops off the
     * top '0' bytes
     */
    if (flen > num) {
        RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
               RSA_R_DATA_GREATER_THAN_MOD_LEN);
        goto err;
    }
    
    /* make data into a big number */
    if (BN_bin2bn(from, (int)flen, f) == NULL)
        goto err;
    
    if (BN_ucmp(f, rsa->n) >= 0) {
        RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT,
               RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
        goto err;
    }
    
    /*if (!(rsa->flags & RSA_FLAG_NO_BLINDING)) {
        blinding = rsa_get_blinding(rsa, &local_blinding, ctx);
        if (blinding == NULL) {
            RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }*/
    
    if (blinding != NULL) {
        if (!local_blinding && ((unblind = BN_CTX_get(ctx)) == NULL)) {
            RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        /*if (!rsa_blinding_convert(blinding, f, unblind, ctx))
            goto err;*/
    }
    
    /* do the decrypt */
    if ((rsa->flags & RSA_FLAG_EXT_PKEY) ||
        ((rsa->p != NULL) &&
         (rsa->q != NULL) &&
         (rsa->dmp1 != NULL) && (rsa->dmq1 != NULL) && (rsa->iqmp != NULL))) {
            if (!rsa->meth->rsa_mod_exp(ret, f, rsa, ctx))
                goto err;
        } else {
            BIGNUM *d = NULL, *local_d = NULL;
            
            if (!(rsa->flags & RSA_FLAG_NO_CONSTTIME)) {
                local_d = d = BN_new();
                if (!d) {
                    RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, ERR_R_MALLOC_FAILURE);
                    goto err;
                }
                BN_with_flags(d, rsa->d, BN_FLG_CONSTTIME);
            } else
                d = rsa->d;
            
            if (rsa->flags & RSA_FLAG_CACHE_PUBLIC)
                if (!BN_MONT_CTX_set_locked
                    (&rsa->_method_mod_n, CRYPTO_LOCK_RSA, rsa->n, ctx)) {
                    BN_free(local_d);
                    goto err;
                }
            if (!rsa->meth->bn_mod_exp(ret, f, d, rsa->n, ctx,
                                       rsa->_method_mod_n)) {
                BN_free(local_d);
                goto err;
            }
            BN_free(local_d);
        }
    
    if (blinding)
        /*if (!rsa_blinding_invert(blinding, ret, unblind, ctx))
            goto err;*/
    
    p = buf;
    j = BN_bn2bin(ret, p);      /* j is only used with no-padding mode */
    
    switch (padding) {
        case RSA_PKCS1_PADDING:
            r = RSA_padding_check_PKCS1_type_2(to, num, buf, j, num);
            break;
        case RSA_PKCS1_OAEP_PADDING:
            r = RSA_padding_check_PKCS1_OAEP(to, num, buf, j, num, NULL, 0);
            break;
        case RSA_SSLV23_PADDING:
            r = RSA_padding_check_SSLv23(to, num, buf, j, num);
            break;
        case RSA_NO_PADDING:
            r = RSA_padding_check_none(to, num, buf, j, num);
            break;
        default:
            RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
            goto err;
    }
    if (r < 0)
        RSAerr(RSA_F_RSA_EAY_PRIVATE_DECRYPT, RSA_R_PADDING_CHECK_FAILED);
    
err:
    if (ctx != NULL)
        BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    //OPENSSL_clear_free(buf, num);
    return (r);
}

NSData *CTOpenSSLGeneratePrivateRSAKey(int keyLength, CTOpenSSLPrivateKeyFormat format)
{
    CTOpenSSLInitialize();

    BIGNUM *someBigNumber = BN_new();
    RSA *key = RSA_new();

    BN_set_word(someBigNumber, RSA_F4);

    if (!RSA_generate_key_ex(key, keyLength, someBigNumber, NULL)) {
        [NSException raise:NSInternalInconsistencyException format:@"RSA_generate_key_ex() failed"];
    }

    BIO *bio = BIO_new(BIO_s_mem());

	switch (format) {
		case CTOpenSSLPrivateKeyFormatDER:
			i2d_RSAPrivateKey_bio(bio, key);
			break;
		case CTOpenSSLPrivateKeyFormatPEM:
			PEM_write_bio_RSAPrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
			break;
		default:
			return nil;
	}

    char *bioData = NULL;
    long bioDataLength = BIO_get_mem_data(bio, &bioData);
    NSData *result = [NSData dataWithBytes:bioData length:bioDataLength];

    RSA_free(key);
    BN_free(someBigNumber);
    BIO_free(bio);

    return result;
}

NSData *CTOpenSSLExtractPublicKeyFromPrivateRSAKey(NSData *privateKeyData)
{
    CTOpenSSLInitialize();

    BIO *privateBIO = NULL;
	RSA *privateRSA = NULL;

	if (!(privateBIO = BIO_new_mem_buf((unsigned char*)privateKeyData.bytes, (int)privateKeyData.length))) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot allocate new BIO memory buffer"];
	}

	if (!PEM_read_bio_RSAPrivateKey(privateBIO, &privateRSA, NULL, NULL)) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot read private RSA BIO with PEM_read_bio_RSAPrivateKey()!"];
	}

	int RSAKeyError = RSA_check_key(privateRSA);
	if (RSAKeyError != 1) {
        [NSException raise:NSInternalInconsistencyException format:@"private RSA key is invalid: %d", RSAKeyError];
	}

    BIO *bio = BIO_new(BIO_s_mem());

    if (!PEM_write_bio_RSA_PUBKEY(bio, privateRSA)) {
        [NSException raise:NSInternalInconsistencyException format:@"unable to write public key"];
        return nil;
    }

    char *bioData = NULL;
    long bioDataLength = BIO_get_mem_data(bio, &bioData);
    NSData *result = [NSData dataWithBytes:bioData length:bioDataLength];

    RSA_free(privateRSA);
    BIO_free(bio);

    return result;
}

NSData *CTOpenSSLRSAEncrypt(NSData *publicKeyData, NSData *data)
{
	return CTOpenSSLRSAEncryptWithPadding(publicKeyData, data, RSA_PKCS1_PADDING);
}

NSData *CTOpenSSLRSAEncryptWithPadding(NSData *publicKeyData, NSData *data, int padding)
{
    CTOpenSSLInitialize();

    unsigned char *inputBytes = (unsigned char *)data.bytes;
    long inputLength = data.length;

    BIO *publicBIO = NULL;
    RSA *publicRSA = NULL;

    if (!(publicBIO = BIO_new_mem_buf((unsigned char *)publicKeyData.bytes, (int)publicKeyData.length))) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot allocate new BIO memory buffer"];
    }

    if (!PEM_read_bio_RSA_PUBKEY(publicBIO, &publicRSA, NULL, NULL)) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot read public RSA BIO with PEM_read_bio_RSA_PUBKEY()!"];
    }

    unsigned char *outputBuffer = (unsigned char *)malloc(RSA_size(publicRSA));
    int outputLength = 0;

    if (!(outputLength = RSA_public_encrypt((int)inputLength, inputBytes, (unsigned char *)outputBuffer, publicRSA, padding))) {
        [NSException raise:NSInternalInconsistencyException format:@"RSA public encryption RSA_public_encrypt() failed"];
    }

    if (outputLength == -1) {
        [NSException raise:NSInternalInconsistencyException format:@"Encryption failed with error %s (%s)", ERR_error_string(ERR_get_error(), NULL), ERR_reason_error_string(ERR_get_error())];
    }

    NSData *encryptedData = [NSData dataWithBytesNoCopy:outputBuffer length:outputLength freeWhenDone:YES];

    BIO_free(publicBIO);
    RSA_free(publicRSA);

    return encryptedData;
}

NSData *CTOpenSSLRSADecrypt(NSData *privateKeyData, NSData *data)
{
	return CTOpenSSLRSADecryptWithPadding(privateKeyData, data, RSA_PKCS1_PADDING);
}

NSData *CTOpenSSLRSADecryptWithPadding(NSData *privateKeyData, NSData *data, int padding)
{
    CTOpenSSLInitialize();

    unsigned char *inputBytes = (unsigned char *)data.bytes;
    long inputLength = data.length;

    BIO *privateBIO = NULL;
    RSA *privateRSA = NULL;

    if (!(privateBIO = BIO_new_mem_buf((unsigned char*)privateKeyData.bytes, (int)privateKeyData.length))) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot allocate new BIO memory buffer"];
    }

    if (!PEM_read_bio_RSAPrivateKey(privateBIO, &privateRSA, NULL, NULL)) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot read private RSA BIO with PEM_read_bio_RSAPrivateKey()!"];
    }

    int RSAKeyError = RSA_check_key(privateRSA);
    if (RSAKeyError != 1) {
        [NSException raise:NSInternalInconsistencyException format:@"private RSA key is invalid: %d", RSAKeyError];
    }

    unsigned char *outputBuffer = (unsigned char *)malloc(RSA_size(privateRSA));
    int outputLength = 0;

    /*if (!(outputLength = RSA_private_decrypt((int)inputLength, inputBytes, outputBuffer, privateRSA, padding))) {
        [NSException raise:NSInternalInconsistencyException format:@"RSA private decrypt RSA_private_decrypt() failed"];
    }*/
    
    RSA_eay_private_decrypt((int)inputLength, inputBytes, outputBuffer, privateRSA, padding);

    if (outputLength == -1) {
        [NSException raise:NSInternalInconsistencyException format:@"Encryption failed with error %s (%s)", ERR_error_string(ERR_get_error(), NULL), ERR_reason_error_string(ERR_get_error())];
    }

    NSData *decryptedData = [NSData dataWithBytesNoCopy:outputBuffer length:outputLength freeWhenDone:YES];

    BIO_free(privateBIO);
    RSA_free(privateRSA);

    return decryptedData;
}

NSData *CTOpenSSLRSASignWithPrivateKey(NSData *privateKeyData, NSData *data, CTOpenSSLDigestType digestType)
{
    CTOpenSSLInitialize();

    data = CTOpenSSLGenerateDigestFromData(data, digestType);

    unsigned char *inputBytes = (unsigned char *)data.bytes;
    long inputLength = data.length;

    BIO *privateBIO = NULL;
    RSA *privateRSA = NULL;

    if (!(privateBIO = BIO_new_mem_buf((unsigned char*)privateKeyData.bytes, (int)privateKeyData.length))) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot allocate new BIO memory buffer"];
    }

    if (!PEM_read_bio_RSAPrivateKey(privateBIO, &privateRSA, NULL, NULL)) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot read private RSA BIO with PEM_read_bio_RSAPrivateKey()!"];
    }

    int RSAKeyError = RSA_check_key(privateRSA);
    if (RSAKeyError != 1) {
        [NSException raise:NSInternalInconsistencyException format:@"private RSA key is invalid: %d", RSAKeyError];
    }

    unsigned char *outputBuffer = (unsigned char *)malloc(RSA_size(privateRSA));
    unsigned int outputLength = 0;

    int type = CTOpenSSLRSASignTypeFromDigestType(digestType);

    if (!RSA_sign(type, inputBytes, (unsigned int)inputLength, outputBuffer, &outputLength, privateRSA)) {
        [NSException raise:NSInternalInconsistencyException format:@"RSA_sign() failed"];
    }

    if (outputLength == -1) {
        [NSException raise:NSInternalInconsistencyException format:@"Encryption failed with error %s (%s)", ERR_error_string(ERR_get_error(), NULL), ERR_reason_error_string(ERR_get_error())];
    }

    NSData *decryptedData = [NSData dataWithBytesNoCopy:outputBuffer length:outputLength freeWhenDone:YES];

    BIO_free(privateBIO);
    RSA_free(privateRSA);

    return decryptedData;
}

BOOL CTOpenSSLRSAVerifyWithPublicKey(NSData *publicKeyData, NSData *data, NSData *signature, CTOpenSSLDigestType digestType)
{
    CTOpenSSLInitialize();

    data = CTOpenSSLGenerateDigestFromData(data, digestType);

    unsigned char *inputBytes = (unsigned char *)data.bytes;
    long inputLength = data.length;

    unsigned char *signatureBytes = (unsigned char *)signature.bytes;
    long signatureLength = signature.length;

    BIO *publicBIO = NULL;
    RSA *publicRSA = NULL;

    if (!(publicBIO = BIO_new_mem_buf((unsigned char *)publicKeyData.bytes, (int)publicKeyData.length))) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot allocate new BIO memory buffer"];
    }

    if (!PEM_read_bio_RSA_PUBKEY(publicBIO, &publicRSA, NULL, NULL)) {
        [NSException raise:NSInternalInconsistencyException format:@"cannot read public RSA BIO with PEM_read_bio_RSA_PUBKEY()!"];
    }

    int type = CTOpenSSLRSASignTypeFromDigestType(digestType);

    BOOL signatureIsVerified = RSA_verify(type, inputBytes, (unsigned int)inputLength, signatureBytes, (unsigned int)signatureLength, publicRSA) == 1;

    BIO_free(publicBIO);
    RSA_free(publicRSA);

    return signatureIsVerified;
}
