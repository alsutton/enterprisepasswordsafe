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
import java.util.StringTokenizer;
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
public final class ActiveDirectoryLoginModule
    extends BaseActiveDirectoryLoginModule
	implements LoginModule, AuthenticationSourceModule {

    /**
     * The parameter name in the options for the LDAP provider base.
     */

    public static final String DOMAIN_CONTROLLER_PARAMETERNAME = "ad.domaincontroller";

    /**
     * The parameter name for the location of the OU relative to the domain information.
     */

    public static final String USERS_OU_LOCATION = "ad.oulocation";

    /**
     * The default ou location if nothing is specified.
     */

    public static final String DEFAULT_USER_OU = "CN=Users";

    /**
     * The parameter name for the SSL on/off flag.
     */

    public static final String LDAPS_PARAMETERNAME = "ad.ldaps";

    /**
     * The parameter name in the options for the search base.
     */

    public static final String DOMAIN_PARAMETERNAME = "ad.domain";

    /**
     * The options passed to this module.
     */

    private Map<String, ?> options;

    /**
     * The callback handler.
     */

    private CallbackHandler callbackHandler;

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

        String sslFlag = (String) options.get(LDAPS_PARAMETERNAME);
        boolean sslOff = sslFlag == null || sslFlag.charAt(0) == 'N';
        String ldapProtocol;
        if( sslOff ) {
        	ldapProtocol="ldap://";
        } else {
        	ldapProtocol="ldaps://";
        }

        StringBuffer providerUrlBuffer = new StringBuffer();
        providerUrlBuffer.append(ldapProtocol);
        providerUrlBuffer.append(options.get(DOMAIN_CONTROLLER_PARAMETERNAME));
        providerUrlBuffer.append('/');
        String providerUrl = providerUrlBuffer.toString();
        try {
            Hashtable<String,Object> env = new Hashtable<String,Object>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, providerUrl);

            DirContext context = new InitialDirContext(env);
            try {
                StringBuffer searchFilter = new StringBuffer();
                searchFilter.append("(&(objectClass=user)(sAMAccountName=");
                searchFilter.append(nameCallback.getName());
                searchFilter.append("))");

                String password = new String(passwordCallback.getPassword());

                Hashtable<String,Object> rebindEnv = new Hashtable<String,Object>();
                rebindEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

                rebindEnv.put(Context.PROVIDER_URL, providerUrl);
                rebindEnv.put(Context.SECURITY_AUTHENTICATION, "simple");

                // Construct the search base
                String userRelativePath = (String) options.get(USERS_OU_LOCATION);
                if( userRelativePath == null ) {
                	userRelativePath = DEFAULT_USER_OU;
                }

                StringBuffer searchBaseBuffer = new StringBuffer(userRelativePath);
                searchBaseBuffer.append(", ");
                StringTokenizer tokenizer =
                    new StringTokenizer((String) options.get(DOMAIN_PARAMETERNAME), ".");
                while (tokenizer.hasMoreTokens()) {
                    searchBaseBuffer.append("dc=");
                    searchBaseBuffer.append(tokenizer.nextToken());
                    searchBaseBuffer.append(", ");
                }
                // Remove the last comma.
                searchBaseBuffer.delete(searchBaseBuffer.length() - 2, searchBaseBuffer.length());

                String searchBase = searchBaseBuffer.toString();
                SearchControls searchControls = new SearchControls();
                searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                NamingEnumeration<SearchResult> matches =
                    context.search(
                        searchBase,
                        searchFilter.toString(),
                        searchControls
                     );

                while (matches.hasMore() && !loginOK) {
                    SearchResult thisResult = matches.next();
                    String dn = thisResult.getName().toString();
                    if(canBindToServer(rebindEnv, searchBase, dn, password)) {
                        return true;
                    }
                }
            } finally {
                context.close();
            }
        } catch (Exception ex) {
            Logger.
                getLogger(ActiveDirectoryLoginModule.class.getName()).
                    log(Level.WARNING, "Problem during authentication ", ex);
        }

        throw new FailedLoginException("Your Active Directory Server did not authenticate you.");
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
        options = newOptions;
    }

    /**
     * Get the configuration options for this module.
     *
     * @return The set of configuration options
     */

	@Override
	public Set<AuthenticationSourceConfigurationOption> getConfigurationOptions() {
    	Set<AuthenticationSourceConfigurationOption> newConfigurationOptions =
    		new TreeSet<AuthenticationSourceConfigurationOption>();

    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					1,
    					"Domain Controller Server Name",
    					"ad.domaincontroller",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					"pdc01"
    				)
    		);

    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					2,
    					"Location of users branch relative to the domain",
    					"ad.oulocation",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					"cn=Users"
    				)
    		);

    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					3,
    					"Domain to authenticate",
    					"ad.domain",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					"mydomain.mycompany.com"
    				)
    		);

    	Set<AuthenticationSourceConfigurationOptionValue> yesNoOptions =
    		new TreeSet<AuthenticationSourceConfigurationOptionValue>();
    	yesNoOptions.add(
    				new AuthenticationSourceConfigurationOptionValue("Yes", "Y")
    			);
    	yesNoOptions.add(
				new AuthenticationSourceConfigurationOptionValue("No", "N")
			);
    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					6,
    					"Connect using SSL",
    					"ad.ldaps",
    					AuthenticationSourceConfigurationOption.RADIO_BOX,
    					yesNoOptions,
    					"N"
    				)
    		);

    	return newConfigurationOptions;
	}

	/**
	 * Get the configuration notes for this source.
	 *
	 * @return The notes for the configuration page for this source.
	 */

	@Override
	public String getConfigurationNotes() {
		return "Warning: Connecting over SSL may not work if your Active Directory Server is using "+
			   "an SSL Certificate from a certificate authority which is not known by your Java "+
			   "Virtual Machine.\n\n"+
			   "Please Note : In order to successfully authenticate users against Active Directory you must "+
			   "configure your Active Directory server to allow the Everyone group to perform the "+
			   "following operations;\n\n"+
			   "List Contents - on the user container for the domain you are authenticating against\n"+
			   "Read All Properties - on User objects\n"+
			   "Read All Properties - on Group objects";
	}
}
