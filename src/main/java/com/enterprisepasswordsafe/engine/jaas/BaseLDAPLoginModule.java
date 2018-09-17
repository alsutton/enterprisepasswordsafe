package com.enterprisepasswordsafe.engine.jaas;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import java.util.Hashtable;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

abstract class BaseLDAPLoginModule extends BaseLoginModule{

    transient Map<String, ?> options;

    transient CallbackHandler callbackHandler;

    @Override
    public void initialize(final Subject newSubject,
                           final CallbackHandler newCallbackHandler,
                           final Map<String, ?> newSharedState, final Map<String, ?> newOptions) {
        subject = newSubject;
        callbackHandler = newCallbackHandler;
        loginOK = false;
        commitOK = false;
        options = newOptions;
    }

    boolean canBindToServer(final Hashtable<String, Object> rebindEnvironment, final String searchBase,
                          final String dn, final String password) {
        try {
            attemptBind(rebindEnvironment, dn + ", " +searchBase, password);
            loginOK = true;
            return true;
        } catch (Exception ex) {
            Logger.getAnonymousLogger().log(Level.WARNING, "Failed to bind with " + dn, ex);
        }
        return false;
    }

    void attemptBind(final Hashtable<String,Object> env, final String dn, final String password)
            throws NamingException {
        env.put(Context.SECURITY_PRINCIPAL, dn);
        env.put(Context.SECURITY_CREDENTIALS, password);
        DirContext ctx = new InitialDirContext(env);
        ctx.close();
    }

}
