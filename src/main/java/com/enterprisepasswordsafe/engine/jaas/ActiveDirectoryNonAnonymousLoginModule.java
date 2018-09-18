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
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

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

    public static final String DOMAIN_USER_PASS_PARAMETERNAME = "ad.userpass";

    /**
     * The parameter name in the options for the LDAP provider base.
     */

    public static final String DOMAIN_CONTROLLER_PARAMETERNAME = "ad.domaincontroller";

    /**
     * The parameter name in the options for the search base.
     */

    public static final String DOMAIN_PARAMETERNAME = "ad.domain";

    @Override
	public boolean login() throws LoginException {
        loginOK = false;
        if (callbackHandler == null) {
            throw new LoginException("Callback handler not defined.");
        }

        UserDetails userDetails = getUserDetailsFromCallbacks();
        String providerUrl = getBindUrl(options.get(DOMAIN_CONTROLLER_PARAMETERNAME).toString());
        try {
            List<String> userCNs = getCandidateUserCNs(providerUrl, userDetails);
            if( userCNs.size() > 0 ) {
                Hashtable<String,Object> rebindEnv = getSimpleAuthEnvironment(providerUrl);
                for(String userCN : userCNs) {
                	String bindDN = constructUserDN(userCN);
                    try {
                        attemptBind(rebindEnv, bindDN, userDetails.password);
                        loginOK = true;
                        return true;
                    } catch (Exception ex) {
                        Logger.getLogger(ActiveDirectoryNonAnonymousLoginModule.class.getName()).
                                log(Level.WARNING, "Failed to bind with " + bindDN, ex);
                    }
                }
            } else {
                Logger.getLogger(ActiveDirectoryNonAnonymousLoginModule.class.getName()).
                    log(Level.WARNING, "No matches for " + userDetails.username + " in " + constructLDAPSearchBase());
            }
        } catch (Exception ex) {
            Logger.getLogger(ActiveDirectoryNonAnonymousLoginModule.class.getName()).
                    log(Level.WARNING, "Problem during authentication ", ex);
        }

        throw new FailedLoginException("Your Active Directory Server did not authenticate you.");
    }

    private void addAuthenticationDetails(Hashtable<String, Object> environment) {
        String bindUserFQDN = (String) options.get(DOMAIN_USER_PARAMETERNAME);
        if( !bindUserFQDN.startsWith("cn=") &&  !bindUserFQDN.contains("\\") ) {
            StringBuffer bindUser = new StringBuffer();
            bindUser.append("cn=").append(bindUserFQDN).append(',');
            constructUserLDAPBase(bindUser);
            bindUserFQDN = bindUser.toString();
        }

        environment.put(Context.SECURITY_AUTHENTICATION, "simple");
        environment.put(Context.SECURITY_PRINCIPAL, bindUserFQDN);
        environment.put(Context.SECURITY_CREDENTIALS, options.get(DOMAIN_USER_PASS_PARAMETERNAME).toString());
    }

    private String constructLDAPSearchBase() {
    	StringBuffer ldapBase = new StringBuffer();
    	constructUserLDAPBase(ldapBase);
        return ldapBase.toString();
    }

    private String constructUserDN(String userCN) {
        StringBuffer bindDNBuffer = new StringBuffer("CN=");
        bindDNBuffer.append(userCN);
        bindDNBuffer.append(',');
        constructUserLDAPBase(bindDNBuffer);
        return bindDNBuffer.toString();
    }

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

    private List<String> getCandidateUserCNs(String providerUrl, UserDetails userDetails)
            throws NamingException {
        Hashtable<String,Object> env = getNoAuthEnvironment(providerUrl);
        addAuthenticationDetails(env);

        List<String> userCNs = new ArrayList<>();
        DirContext context = new InitialDirContext(env);
        try {
            SearchControls searchControls = new SearchControls();
            searchControls.setReturningAttributes(NEEDED_ATTRIBUTES);
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            String searchFilter = "(&(objectClass=user)(sAMAccountName=" + userDetails.username + "))";
            NamingEnumeration<SearchResult> matches = context.search(constructLDAPSearchBase(), searchFilter, searchControls);
            while (matches.hasMore() && !loginOK) {
                SearchResult thisResult = matches.next();
                String userCN = thisResult.getAttributes().get("cn").get().toString();
                userCNs.add(userCN);
            }
        } finally {
            context.close();
        }
        return userCNs;
    }

	@Override
	public Set<AuthenticationSourceConfigurationOption> getConfigurationOptions() {
    	Set<AuthenticationSourceConfigurationOption> newConfigurationOptions = new TreeSet<>();

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

    	Set<AuthenticationSourceConfigurationOptionValue> yesNoOptions = new TreeSet<>();
    	yesNoOptions.add(new AuthenticationSourceConfigurationOptionValue("Yes", "Y"));
    	yesNoOptions.add(new AuthenticationSourceConfigurationOptionValue("No", "N"));
    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption( 6, "Connect using SSL",
    					"ad.ldaps", AuthenticationSourceConfigurationOption.RADIO_BOX,
    					yesNoOptions, "N"));

    	return newConfigurationOptions;
	}

	@Override
	public String getConfigurationNotes() {
		return "Warning: Connecting over SSL may not work if your Active Directory Server is using "+
			   "an SSL Certificate from a certificate authority which is not known by your Java "+
			   "Virtual Machine.";
	}
}
