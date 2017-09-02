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

package com.enterprisepasswordsafe.engine.database;

import com.enterprisepasswordsafe.proguard.JavaBean;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface implemented by all objects which are subject to access control.
 */
public interface AccessControledObject extends JavaBean {
	
	/**
	 * Return the ID of the object
	 * 
	 * @return id The ID of the object.
	 */
	
	public String getId();
	
	/**
	 * Get the key needed to decrypt the object for reading.
	 * 
	 * @return readKey The key needed to decrypt the object for reading.
	 */
	
	public PublicKey getReadKey();

	/**
	 * Get the key needed to encrypt the object for writing.
	 * 
	 * @return readKey The key needed to encrypt the object for writing.
	 */
	
	public PrivateKey getModifyKey();
	
	/**
	 * Whether or not actions on this object should be logged.
	 */

	public boolean isLoggable();
}
