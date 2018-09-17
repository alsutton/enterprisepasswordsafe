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

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.security.Principal;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * JAAS module for handling logging in a user.
 */

public final class LDAPSearchAndBindLoginModule
    extends BaseLDAPLoginModule
	implements LoginModule, AuthenticationSourceModule {

    public static final String PROVIDER_URL_PARAMETERNAME = "jndi.url";

    public static final String SEARCH_BASE_PARAMETERNAME = "jndi.search.base";

    public static final String SEARCH_ATTRIBUTE_PARAMETERNAME = "jndi.search.attr";

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

        UserDetails userDetails = getUserDetailsFromCallbacks();

        try {
            Hashtable<String,Object> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, options.get(PROVIDER_URL_PARAMETERNAME));

            DirContext context = new InitialDirContext(env);
            try {
                String searchAttribute = (String) options.get(SEARCH_ATTRIBUTE_PARAMETERNAME);

                Hashtable<String,Object> rebindEnvironment = new Hashtable<>();
                rebindEnvironment.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                rebindEnvironment.put(Context.PROVIDER_URL, options.get(PROVIDER_URL_PARAMETERNAME));
                rebindEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");

                String searchBase = (String) options.get(SEARCH_BASE_PARAMETERNAME);

                SearchControls searchControls = new SearchControls();
                searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                NamingEnumeration<SearchResult> matches =
                    context.search( searchBase, "(" + searchAttribute + '=' + userDetails.username + ')',
                        searchControls);

                while (matches.hasMore() && !loginOK) {
                    if(canBindToServer(rebindEnvironment, searchBase, matches.next().getName(), userDetails.password)) {
                        return true;
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
     * Get the configuration options for this module.
     * 
     * @return The set of configuration options
     */
    
	public Set<AuthenticationSourceConfigurationOption> getConfigurationOptions() {
    	Set<AuthenticationSourceConfigurationOption> newConfigurationOptions = new TreeSet<>();

    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption(1,
    					"Directory URL", "jndi.url",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,null, "ldap://[machine_name]:389/"));

    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption(2,
    					"Search Base", "jndi.search.base",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,null,null));

    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption(3,
    					"Search Prefix", "jndi.search.attr",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,null,"cn"));
    	
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
