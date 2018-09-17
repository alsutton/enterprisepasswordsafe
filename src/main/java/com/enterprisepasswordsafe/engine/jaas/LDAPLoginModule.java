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
import java.security.Principal;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import com.enterprisepasswordsafe.engine.dbpool.DatabasePool;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePoolFactory;

/**
 * JAAS module for handling logging in a user.
 */
public final class LDAPLoginModule
        extends BaseLDAPLoginModule
	    implements AuthenticationSourceModule {

    /**
     * Abort the login attempt.
     *
     * @return true if this module performed some work, false if not.
     */
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
     * Attempt to log the user in.
     *
     * @return true if the login went well, false if not.
     *
     * @throws LoginException
     *             Thrown if there is a problem with the login.
     */
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
            Hashtable<String,Object> env = new Hashtable<String,Object>();
            env.put(Context.INITIAL_CONTEXT_FACTORY,
                    "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, options.get("url"));
            env.put(Context.SECURITY_AUTHENTICATION, "simple");

            StringBuffer principal = new StringBuffer();
            principal.append(options.get("prefix"));
            principal.append('=');
            principal.append(nameCallback.getName());
            principal.append(',');
            principal.append(options.get("base"));
            env.put(Context.SECURITY_PRINCIPAL, principal.toString());
            env.put(Context.SECURITY_CREDENTIALS, new String(passwordCallback
                    .getPassword()));

            DirContext ctx = new InitialDirContext(env);
            ctx.close();

            loginOK = true;
            return true;
        } catch (Exception ex) {
            Logger.
                getLogger(LDAPSearchAndBindLoginModule.class.getName()).
                    log(Level.WARNING, "Problem during authentication ", ex);
        }

        throw new FailedLoginException("Your LDAP Server did not authenticate you.");
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
    public void initialize(final Subject newSubject,
            final CallbackHandler newCallbackHandler,
            final Map<String,?> newSharedState, final Map<String,?> newOptions) {
        subject = newSubject;
        callbackHandler = newCallbackHandler;
        loginOK = false;
        commitOK = false;
        options = newOptions;
    }

    /**
     * Get the configuration options for this module.
     * 
     * @return The set of configuration options
     */
    
	public Set<AuthenticationSourceConfigurationOption> getConfigurationOptions() {
    	Set<AuthenticationSourceConfigurationOption> newConfigurationOptions = 
    		new TreeSet<AuthenticationSourceConfigurationOption>();
    	
    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					1,
    					"Directory URL",
    					"url",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					"ldap://[machine_name]:389/"  
    				)
    		);

    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					2,
    					"User Base",
    					"base",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					null  
    				)
    		);

    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					3,
    					"Username Prefix",
    					"prefix",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					"cn"  
    				)
    		);
    	
    	return newConfigurationOptions;
	}

	/**
	 * Get the configuration notes for this source.
	 * 
	 * @return The notes for the configuration page for this source.
	 */

	public String getConfigurationNotes() {
		return "The username prefix is prepended to the username, and the user base is appended, "+ 
				"for example if the Username Prefix is \"cn\" and the User Base is "+
				"\"dc=some-corp, dc=com\", when a user attempts to log in with the username "+
				"\"User\" the EPS will attempt to bind to \"cn=User, dc=some-corp, dc=com\" "+
				"using the password supplied by the user.";
	}
}
