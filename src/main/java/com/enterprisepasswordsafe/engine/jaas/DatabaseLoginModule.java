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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.sql.SQLException;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.engine.database.UserDAO;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePool;

/**
 * JAAS module for handling logging in a user using the EPS database..
 */
public final class DatabaseLoginModule implements LoginModule {

    /**
     * The subject being authenticated.
     */

    private Subject subject;

    /**
     * The callback handler.
     */

    private CallbackHandler callbackHandler;

    /**
     * Whether or not the login has succeeded.
     */

    private boolean loginOK;

    /**
     * Whether or not the login commited.
     */

    private boolean commitOK;

    /**
     * Abort the login attempt.
     *
     * @return true if this module performed some work, false if not.
     */

    @Override
	public boolean abort() {
        // If we didn't log in ignore this module
        if (!loginOK) {
            return false;
        }

        if (!commitOK) {
            // If the commit hasn't happened clear out any stored info
            loginOK = false;
        } else {
            // If the login was OK, and the commit was OK we need to log out
            // again.
            logout();
        }

        return true;
    }

    /**
     * Commit the authentication attempt.
     *
     * @return true if the commit was OK, false if not.
     */
    @Override
	public boolean commit() {
        commitOK = false;
        if (!loginOK) {
            return false;
        }

        DatabaseLoginPrincipal principal = DatabaseLoginPrincipal.getInstance();
        Set<Principal> principals = subject.getPrincipals();
        if (!principals.contains(principal)) {
            principals.add(principal);
        }

        commitOK = true;
        return true;
    }

    /**
     * Attempt to log the user in.
     *
     * @return true if the login went well, false if not.
     *
     * @throws LoginException
     *             Thrown if there is a problem with the login.
     */
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
        PasswordCallback passwordCallback = new PasswordCallback("Password",
                false);
        callbacks[1] = passwordCallback;
        try {
            callbackHandler.handle(callbacks);
        } catch (IOException ioe) {
            throw new LoginException(ioe.toString());
        } catch (UnsupportedCallbackException uce) {
            throw new LoginException(uce.toString());
        }

        try {
            // Verify the information.
            User theUser = UserDAO.getInstance().getByName(nameCallback.getName());
            if (theUser == null
             || !theUser.checkPassword(passwordCallback.getPassword())) {
                throw new FailedLoginException(
                        "The details specified were not correct");
            }

            loginOK = true;
        } catch (GeneralSecurityException ex) {
            throw new LoginException(ex.toString());
        } catch (SQLException ex) {
            throw new LoginException(ex.toString());
        } catch (UnsupportedEncodingException ex) {
            throw new LoginException(ex.toString());
        }

        return true;
    }

    /**
     * Log the user out.
     *
     * @return true if the user was logged out without any problems.
     */
    @Override
	public boolean logout() {
        DatabaseLoginPrincipal principal = DatabaseLoginPrincipal.getInstance();
        subject.getPrincipals().remove(principal);
        loginOK = false;
        commitOK = false;

        return true;
    }

    /**
     * Initialise the login module.
     *
     * @param newSubject
     *            The subject being authorised.
     * @param newCallbackHandler
     *            The calklback handler which will obtain the login information.
     * @param newSharedState
     *            The shared state between LoginModules
     * @param newOptions
     *            The options for this LoginModule.
     */
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
