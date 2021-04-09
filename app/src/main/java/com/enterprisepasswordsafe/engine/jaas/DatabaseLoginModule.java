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

import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.database.UserDAO;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Map;

public final class DatabaseLoginModule extends BaseLoginModule {

    @Override
	public boolean login() throws LoginException {
        loginOK = false;
        if (callbackHandler == null) {
            throw new LoginException("Callback handler not defined.");
        }

        // Get the information.
        Callback[] callbacks = new Callback[2];
        NameCallback nameCallback = new NameCallback("Username");
        callbacks[0] = nameCallback;
        PasswordCallback passwordCallback = new PasswordCallback("Password", false);
        callbacks[1] = passwordCallback;
        try {
            callbackHandler.handle(callbacks);
        } catch (IOException | UnsupportedCallbackException e) {
            throw new LoginException(e.toString());
        }

        try {
            // Verify the information.
            User theUser = UserDAO.getInstance().getByName(nameCallback.getName());
            if (theUser == null || !theUser.checkPassword(passwordCallback.getPassword())) {
                throw new FailedLoginException("The details specified were not correct");
            }

            loginOK = true;
        } catch (GeneralSecurityException | SQLException ex) {
            throw new LoginException(ex.toString());
        }

        return true;
    }

    @Override
	public void initialize(final Subject newSubject,
            final CallbackHandler newCallbackHandler,
            final Map<String,?> newSharedState, final Map<String,?> newOptions) {
        subject = newSubject;
        callbackHandler = newCallbackHandler;
        loginOK = false;
        commitOK = false;
    }
}
