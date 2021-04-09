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

import com.enterprisepasswordsafe.model.Decrypter;
import com.enterprisepasswordsafe.model.Encrypter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public final class KeyUtils {


    /**
     * Decrypt an encrypted SecretKey and return the key
     *
     * @param encryptedKey The encrypted key
     * @param keyDecrypter The Decrypter to use to decrypt the key.
     *
     * @return The SecretKey object.
     */

    public static SecretKey decryptSecretKey(final byte[] encryptedKey, final Decrypter keyDecrypter)
    	throws GeneralSecurityException {
        if(encryptedKey == null) {
            return null;
        }
    	byte[] key = keyDecrypter.decrypt(encryptedKey);
		return new SecretKeySpec(key, "AES");
    }
}
