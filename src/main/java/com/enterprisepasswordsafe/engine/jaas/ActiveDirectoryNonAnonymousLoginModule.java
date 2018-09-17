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
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
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
public final class ActiveDirectoryNonAnonymousLoginModule
    extends BaseActiveDirectoryLoginModule
	implements LoginModule, AuthenticationSourceModule {

    /**
     * The parameter name for the location of the OU relative to the domain information.
     */

    public static final String USERS_OU_LOCATION = "ad.useroulocation";

    /**
     * The default ou location if nothing is specified.
     */

    public static final String DEFAULT_USER_OU = "CN=Users";

	/**
	 * The attributes needed from the AD search to rebind as the user.
	 */

	private static final String[] NEEDED_ATTRIBUTES = { "cn" };

    /**
     * The parameter name in the options for the LDAP provider base.
     */

    public static final String DOMAIN_USER_PARAMETERNAME = "ad.user";

    /**
     * The parameter name in the options for the LDAP provider base.
     */

    public static final String LDAPS_PARAMETERNAME = "ad.ldaps";

    /**
     * The parameter name in the options for the LDAP provider base.
     */

    public static final String DOMAIN_USER_PASS_PARAMETERNAME = "ad.userpass";

    /**
     * The parameter name in the options for the LDAP provider base.
     */

    public static final String DOMAIN_CONTROLLER_PARAMETERNAME = "ad.domaincontroller";

    /**
     * The parameter name in the options for the search base.
     */

    public static final String DOMAIN_PARAMETERNAME = "ad.domain";

    /**
     * The options passed to this module.
     */

    private Map<String,?> options;

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
        PasswordCallback passwordCallback = new PasswordCallback("Password",false);
        callbacks[1] = passwordCallback;
        try {
            callbackHandler.handle(callbacks);
        } catch (IOException | UnsupportedCallbackException e) {
            throw new LoginException(e.toString());
        }

        String sslFlag = (String) options.get(LDAPS_PARAMETERNAME);
        boolean sslOff = sslFlag == null || sslFlag.charAt(0) == 'N';
        String ldapProtocol = sslOff ? "ldap://" : "ldaps://";
        StringBuffer providerUrlBuffer = new StringBuffer();
        providerUrlBuffer.append(ldapProtocol);
        providerUrlBuffer.append(options.get(DOMAIN_CONTROLLER_PARAMETERNAME));
        providerUrlBuffer.append('/');
        String providerUrl = providerUrlBuffer.toString();

        try {
        	String bindpassword = (String) options.get(DOMAIN_USER_PASS_PARAMETERNAME);
            Hashtable<String,Object> env = new Hashtable<String,Object>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, providerUrl);

            String bindUserFQDN = (String) options.get(DOMAIN_USER_PARAMETERNAME);
            if( bindUserFQDN.startsWith("cn=") == false
            &&  bindUserFQDN.indexOf("\\") == -1 ) {
            	StringBuffer bindUser = new StringBuffer();
            	bindUser.append("cn=");
            	bindUser.append(bindUserFQDN);
            	bindUser.append(',');
            	constructUserLDAPBase(bindUser);
            	bindUserFQDN = bindUser.toString();
            }

			env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, bindUserFQDN);
            env.put(Context.SECURITY_CREDENTIALS, bindpassword);

			List<String> userCNs = new ArrayList<String>();
            DirContext context = new InitialDirContext(env);
            try {
                SearchControls searchControls = new SearchControls();
                searchControls.setReturningAttributes(NEEDED_ATTRIBUTES);
                searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

                StringBuffer searchFilter = new StringBuffer();
                searchFilter.append("(&(objectClass=user)(sAMAccountName=");
                searchFilter.append(nameCallback.getName());
                searchFilter.append("))");

				NamingEnumeration<SearchResult> matches =
                        context.search(constructLDAPSearchBase(), searchFilter.toString(), searchControls);

	            while (matches.hasMore() && !loginOK) {
                	SearchResult thisResult = matches.next();
                	String userCN = thisResult.getAttributes().get("cn").get().toString();
                	userCNs.add(userCN);
                }
            } finally {
                context.close();
            }

            if( userCNs.size() > 0 ) {
                Hashtable<String,Object> rebindEnv = new Hashtable<String,Object>();
                rebindEnv.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                rebindEnv.put(Context.PROVIDER_URL, providerUrl);
                rebindEnv.put(Context.SECURITY_AUTHENTICATION, "simple");

                String password = new String(passwordCallback.getPassword());

                for(String userCN : userCNs) {
                    StringBuffer bindDNBuffer = new StringBuffer("CN=");
                	bindDNBuffer.append(userCN);
                	bindDNBuffer.append(',');
                	constructUserLDAPBase(bindDNBuffer);

                	String bindDN = bindDNBuffer.toString();
                    try {
                        attemptBind(rebindEnv, bindDN, password);
                        loginOK = true;
                        return true;
                    } catch (Exception ex) {
                        Logger.getLogger(ActiveDirectoryNonAnonymousLoginModule.class.getName()).
                                log(Level.WARNING, "Failed to bind with " + bindDN, ex);
                    }
                }
            } else {
                Logger.getLogger(ActiveDirectoryNonAnonymousLoginModule.class.getName()).
                    log(Level.WARNING, "No matches for " + nameCallback.getName() + " in " +
                    		constructLDAPSearchBase());
            }
        } catch (Exception ex) {
            Logger.getLogger(ActiveDirectoryNonAnonymousLoginModule.class.getName()).
                    log(Level.WARNING, "Problem during authentication ", ex);
        }

        throw new FailedLoginException("Your Active Directory Server did not authenticate you.");
    }

    /**
     * Constructs the LDAP representation of the AD domain location.
     *
     * @return the LDAP location of the domain.
     */

    private String constructLDAPSearchBase() {
    	StringBuffer ldapBase = new StringBuffer();
    	constructUserLDAPBase(ldapBase);
        return ldapBase.toString();
    }

    /**
     * Constructs the LDAP representation of the AD domain location.
     */

    private void constructUserLDAPBase(StringBuffer userLDAPBase) {
        // Construct the search base
        String userRelativePath = (String) options.get(USERS_OU_LOCATION);
        if( userRelativePath == null ) {
        	userRelativePath = DEFAULT_USER_OU;
        }

        userLDAPBase.append(userRelativePath);
        userLDAPBase.append(',');
        constructLDAPBase(userLDAPBase);
    }

    /**
     * Constructs the LDAP representation of the AD domain location.
     *
     * @param ldapBase The StringBuffer to construct the base in.
     */

    private void constructLDAPBase(StringBuffer ldapBase) {
        StringTokenizer tokenizer =
            new StringTokenizer((String) options.get(DOMAIN_PARAMETERNAME), ".");
        while (tokenizer.hasMoreTokens()) {
        	ldapBase.append("DC=");
        	ldapBase.append(tokenizer.nextToken());
        	ldapBase.append(",");
        }
        // Remove the last comma.
        ldapBase.delete(ldapBase.length() - 1, ldapBase.length());
    }

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

	@Override
	public Set<AuthenticationSourceConfigurationOption> getConfigurationOptions() {
    	Set<AuthenticationSourceConfigurationOption> newConfigurationOptions = new TreeSet<AuthenticationSourceConfigurationOption>();

    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(1, "Domain Controller Server Name",
    					"ad.domaincontroller", AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null, "pdc01"));
    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					2, "Location of users branch relative\nto the domain",
    					"ad.useroulocation", AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null, "cn=Users"));
    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption( 3, "Domain to authenticate",
    					"ad.domain", AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null, "mydomain.mycompany.com"));
    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(4, "Name or LDAP FQDN of user to connect as",
    					"ad.user", AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null, "EPS User"));
    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption( 5, "Password to connect with",
    					"ad.userpass", AuthenticationSourceConfigurationOption.PASSWORD_INPUT_BOX,
    					null, "null"));

    	Set<AuthenticationSourceConfigurationOptionValue> yesNoOptions = new TreeSet<AuthenticationSourceConfigurationOptionValue>();
    	yesNoOptions.add(new AuthenticationSourceConfigurationOptionValue("Yes", "Y"));
    	yesNoOptions.add(new AuthenticationSourceConfigurationOptionValue("No", "N"));
    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption( 6, "Connect using SSL",
    					"ad.ldaps", AuthenticationSourceConfigurationOption.RADIO_BOX,
    					yesNoOptions, "N"));

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
			   "Virtual Machine.";
	}
}
