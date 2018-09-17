package com.enterprisepasswordsafe.engine.jaas;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
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
        if (!principals.contains(principal)) {
            principals.add(principal);
        }

        commitOK = true;
        return true;
    }
}
