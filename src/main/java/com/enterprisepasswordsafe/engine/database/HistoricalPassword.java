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

/*
 * Password.java
 *
 * Created on 28 June 2003, 11:57
 */

package com.enterprisepasswordsafe.engine.database;

import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.utils.PasswordUtils;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Object representing a password from the past.
 */
public final class HistoricalPassword
        extends PasswordBase {

    private static final PasswordUtils<HistoricalPassword> passwordUtils = new PasswordUtils<>();

    /**
     * The timestamp field.
     */

    private final long timestamp;

    /**
     * Creates a new instance of a historical Password.
     *
     * @param passwordId The ID of the password
     * @param data The data for the password
     * @param ac The AccessControl used to access the password.
     * @param timestamp The timestamp for when the password data was valid.

     */

    public HistoricalPassword(final String passwordId, final byte[] data, final AccessControl ac, final long timestamp)
            throws IOException, GeneralSecurityException {
        super(passwordId);
        this.timestamp = timestamp;
        passwordUtils.decrypt(this, ac, data);
    }

    /**
     * Gets the timestamp for when the password was valid.
     *
     * @return The timestamp for this password.
     */

    public long getTimestamp() {
        return timestamp;
    }

    /**
     * All accesses to historical passwords should be logged.
     */
    @Override
	public boolean isLoggable() {
		return true;
	}
}
