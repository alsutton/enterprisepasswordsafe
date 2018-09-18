package com.enterprisepasswordsafe.engine.jaas;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.security.Principal;
import java.util.Set;

public abstract class BaseLoginModule implements LoginModule {
    boolean commitOK;
    boolean loginOK;

    Subject subject;

    CallbackHandler callbackHandler;

    public boolean logout() {
        DatabaseLoginPrincipal principal = DatabaseLoginPrincipal.getInstance();
        subject.getPrincipals().remove(principal);
        loginOK = false;
        commitOK = false;

        return true;
    }

    public boolean commit() {
        commitOK = false;
        if (!loginOK) {
            return false;
        }

        DatabaseLoginPrincipal principal = DatabaseLoginPrincipal.getInstance();
        Set<Principal> principals = subject.getPrincipals();
        principals.add(principal);

        commitOK = true;
        return true;
    }

    @Override
    public boolean abort() {
        if (!loginOK) {
            return false;
        }

        if (commitOK) {
            logout();
        }
        loginOK = false;

        return true;
    }


    UserDetails getUserDetailsFromCallbacks() throws LoginException {
        Callback[] callbacks = new Callback[2];
        NameCallback nameCallback = new NameCallback("Username");
        callbacks[0] = nameCallback;
        PasswordCallback passwordCallback = new PasswordCallback("Password",false);
        callbacks[1] = passwordCallback;
        try {
            callbackHandler.handle(callbacks);
        } catch (Exception e) {
            throw new LoginException(e.getMessage());
        }

        String username = nameCallback.getName();
        if( username == null || username.length() == 0) {
            throw new FailedLoginException("You must enter a username.");
        }

        char[] passwordChars = passwordCallback.getPassword();
        if( passwordChars == null || passwordChars.length == 0) {
            throw new FailedLoginException("You must enter a password.");
        }

        return new UserDetails(username, new String(passwordCallback.getPassword()));
    }

    static class UserDetails {
        String username;
        String password;

        UserDetails(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }
}
