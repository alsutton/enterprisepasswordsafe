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
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
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

/**
 * JAAS module for handling logging in a user.
 */

public final class LDAPSearchAndBindLoginModule
	implements LoginModule, AuthenticationSourceModule {

    /**
     * The parameter name in the options for the LDAP provider base.
     */

    public static final String PROVIDER_URL_PARAMETERNAME = "jndi.url";

    /**
     * The parameter name in the options for the search base.
     */

    public static final String SEARCH_BASE_PARAMETERNAME = "jndi.search.base";

    /**
     * The parameter name in the options for the search attribute.
     */

    public static final String SEARCH_ATTRIBUTE_PARAMETERNAME = "jndi.search.attr";

    /**
     * The subject being authenticated.
     */

    private Subject subject;

    /**
     * The options passed to this module.
     */

    private Map<String,?> options;

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
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, options.get(PROVIDER_URL_PARAMETERNAME));

            DirContext context = new InitialDirContext(env);
            try {
                String searchAttribute = (String) options.get(SEARCH_ATTRIBUTE_PARAMETERNAME);
                StringBuffer searchFilter = new StringBuffer();
                searchFilter.append('(');
                searchFilter.append(searchAttribute);
                searchFilter.append('=');
                searchFilter.append(nameCallback.getName());
                searchFilter.append(')');

                String password = new String(passwordCallback.getPassword());

                Hashtable<String,Object> rebindEnv = new Hashtable<String,Object>();
                rebindEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                rebindEnv.put(Context.PROVIDER_URL, options.get(PROVIDER_URL_PARAMETERNAME));
                rebindEnv.put(Context.SECURITY_AUTHENTICATION, "simple");

                String searchBase = (String) options.get(SEARCH_BASE_PARAMETERNAME);

                SearchControls searchControls = new SearchControls();
                searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                NamingEnumeration<SearchResult> matches =
                    context.search(
                        searchBase,
                        searchFilter.toString(),
                        searchControls
                     );

                while (matches.hasMore() && !loginOK) {
                    SearchResult thisResult = (SearchResult) matches.next();
                    String dn = thisResult.getName().toString();
                    try {
                        StringBuffer fullDN = new StringBuffer(dn.length() + searchBase.length() + 2);
                        fullDN.append(dn);
                        fullDN.append(", ");
                        fullDN.append(searchBase);
                        attemptBind(rebindEnv, fullDN.toString(), password);
                        loginOK = true;
                        return true;
                    } catch (Exception ex) {
                        Logger.
                            getLogger(LDAPSearchAndBindLoginModule.class.getName()).
                                log(Level.WARNING, "Failed to bind with " + dn, ex);
                    }
                }
            } finally {
                context.close();
            }
        } catch (Exception ex) {
            Logger.
                getLogger(LDAPSearchAndBindLoginModule.class.getName()).
                    log(Level.WARNING, "Problem during authentication ", ex);
        }

        throw new FailedLoginException("Your LDAP Server did not authenticate you.");
    }

    /**
     * Attempt to bind the the directory using a given DN value.
     *
     * @param env The environment to use to attempt the bind.
     * @param dn The DN value to use for the attempt.
     * @param password The password the user is attempt to use to log in.
     *
     * @throws NamingException Thrown if there is a problem logging in.
     */

    private void attemptBind(final Hashtable<String,Object> env, final String dn,
            final String password)
        throws NamingException {
        env.put(Context.SECURITY_PRINCIPAL, dn);
        env.put(Context.SECURITY_CREDENTIALS, password);
        DirContext ctx = new InitialDirContext(env);
        ctx.close();
    }

    /**
     * Log the user out.
     *
     * @return true if the user was logged out without any problems.
     */
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
    public void initialize(final Subject newSubject,
            final CallbackHandler newCallbackHandler,
            final Map<String, ?> newSharedState, final Map<String,?> newOptions) {
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
    					"jndi.url",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					"ldap://[machine_name]:389/"  
    				)
    		);

    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					2,
    					"Search Base",
    					"jndi.search.base",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					null  
    				)
    		);

    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					3,
    					"Search Prefix",
    					"jndi.search.attr",
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
		return 		
		"The search prefix is prepended to the username, and the a search is performed "+
		"starting at the search base and working down the LDAP hierarchy. Once a match has been found the "+
		"EPS will attempt to bind to the LDAP directory using distinguished name from the matching entry "+ 
		"to bind to the directory.\n\n"+ 
		"For example if the Search Prefix is \"employeeNumber\" and Search Base is "+
		"\"dc=some-corp, dc=com\", when a user attempts to log in with the username \"1234\" "+ 
		"the EPS will search for \"employeeNumber=1234\" beneath \"dc=some-corp, dc=com\", and will "+
		"then use the distinguished name from any matching entry to bind to the LDAP directory.";
	}
}
