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
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.enterprisepasswordsafe.engine.database.Encrypter;


public class UserAccessKeyEncrypter
	implements Encrypter {

	/**
	 * The password to encrypt with.
	 */

	private final SecretKey encryptionKey;

	/**
	 * Constructor. Stores password
	 * @throws NoSuchAlgorithmException
	 */

	public UserAccessKeyEncrypter(final SecretKey newKey) {
		encryptionKey = newKey;
	}

	/**
	 * Method to perform the encryption.
	 *
	 * @param data The data to encrypt.
	 *
	 * @return The encrypted representation of the data.
	 */

	@Override
	public byte[] encrypt(byte[] data)
		throws GeneralSecurityException {
        Cipher pbeCipher = Cipher.getInstance("AES");
        pbeCipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
        return pbeCipher.doFinal(data);
	}

}
