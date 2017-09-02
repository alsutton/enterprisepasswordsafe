/*
 * Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package com.enterprisepasswordsafe.engine.utils;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.enterprisepasswordsafe.engine.database.Decrypter;
import com.enterprisepasswordsafe.engine.database.Encrypter;

public final class KeyUtils {

    /**
     * Encrypt key are return the encrypted representation.
     *
     * @param Key The key
     * @param keyEncrypter The Encrypter to use to encrypt the key.
     *
     * @return The PrivateKey encrypted representation.
     */

    public static byte[] encryptKey(final Key key, final Encrypter keyEncrypter)
    	throws GeneralSecurityException {
        if(key == null) {
            return null;
        }
        return keyEncrypter.encrypt(key.getEncoded());
    }


    /**
     * Decrypt an encrypted SecretKey and return the key
     *
     * @param encryptedKey The encrypted key
     * @param keyDecrypter The Decrypter to use to decrypt the key.
     *
     * @return The SecretKey object.
     */

    public static SecretKey decryptSecretKey(final byte[] encryptedKey, final Decrypter keyDecrypter)
    	throws SQLException, GeneralSecurityException {
        if(encryptedKey == null) {
            return null;
        }
    	byte[] key = keyDecrypter.decrypt(encryptedKey);
		return new SecretKeySpec(key, "AES");
    }

    /**
     * Decrypt and encrypted PrivateKey and return it.
     *
     * @param encryptedKey The encrypted key
     * @param keyDecrypter The Decrypter to use to decrypt the key.
     *
     * @return The PrivateKey object.
     */

    public static PrivateKey decryptPrivateKey(final byte[] encryptedKey, final Decrypter keyDecrypter)
    	throws SQLException, GeneralSecurityException {
    	byte[] decryptedKeyBytes = keyDecrypter.decrypt(encryptedKey);
        PKCS8EncodedKeySpec skeySpec = new PKCS8EncodedKeySpec(decryptedKeyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePrivate(skeySpec);
    }

    /**
     * Decrypt and encrypted PublicKey and return it.
     *
     * @param encryptedKey The encrypted key
     * @param keyDecrypter The Decrypter to use to decrypt the key.
     *
     * @return The PublicKey object.
     */

    public static PublicKey decryptPublicKey(final byte[] encryptedKey, final Decrypter keyDecrypter)
    	throws SQLException, GeneralSecurityException {
    	byte[] decryptedKeyBytes = keyDecrypter.decrypt(encryptedKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decryptedKeyBytes);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return factory.generatePublic(keySpec);
    }
}
