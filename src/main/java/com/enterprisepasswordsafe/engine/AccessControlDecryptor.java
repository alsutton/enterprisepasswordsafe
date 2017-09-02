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

package com.enterprisepasswordsafe.engine;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import com.enterprisepasswordsafe.engine.database.Decrypter;
import com.enterprisepasswordsafe.engine.database.Encrypter;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Interface implemented by any object capable of decrypting an access control.
 */

public interface AccessControlDecryptor extends ExternalInterface {

    /**
     * Decrypt some data.
     *
     * @param data The encrypted data.
     *
     * @return The unencrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws UnsupportedEncodingException
     */

    byte[] decrypt(byte[] data)
        throws GeneralSecurityException, UnsupportedEncodingException;

    /**
     * Gets the key decrypter method for use with the keystore
     */

    Decrypter getKeyDecrypter();

    /**
     * Gets the key encrypter method for use with the keystore
     */

    Encrypter getKeyEncrypter();

}
