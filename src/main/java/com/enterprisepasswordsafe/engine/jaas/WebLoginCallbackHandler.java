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

package com.enterprisepasswordsafe.engine.jaas;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * The JAAS callback handler.
 */

public final class WebLoginCallbackHandler implements CallbackHandler {

    /**
     * The username for this callback handler.
     */

    private String username;

    /**
     * The password for this callback handler.
     */

    private char[] password;

    /**
     * Constructor. Stores information.
     *
     * @param newUsername The username to store.
     * @param newPassword The password to store.
     */

    public WebLoginCallbackHandler(final String newUsername, final char[] newPassword) {
        username = newUsername;
        password = newPassword;
    }

    /**
     * Handle the callbacks for the authenticator.
     *
     * @param callbacks
     *            The array of callbacks that need to be satisfied.
     *
     * @throws UnsupportedCallbackException Thrown if a callback is passed that is not known.
     */

    public void handle(final Callback[] callbacks)
            throws UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            Callback thisCallback = callbacks[i];
            if (thisCallback instanceof NameCallback) {
                ((NameCallback) thisCallback).setName(username);
            } else if (thisCallback instanceof PasswordCallback) {
                ((PasswordCallback) thisCallback).setPassword(password);
            } else {
                throw new UnsupportedCallbackException(thisCallback,
                        "Unsupported Callback.");
            }
        }

    }

}
