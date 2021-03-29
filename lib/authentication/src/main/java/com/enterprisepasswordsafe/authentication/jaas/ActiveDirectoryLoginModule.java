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

package com.enterprisepasswordsafe.authentication.jaas;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Hashtable;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class ActiveDirectoryLoginModule
    extends BaseActiveDirectoryLoginModule
	implements LoginModule, AuthenticationSourceModule {

    public static final String DOMAIN_CONTROLLER_PARAMETERNAME = "ad.domaincontroller";

    public static final String USERS_OU_LOCATION = "ad.oulocation";

    public static final String DEFAULT_USER_OU = "CN=Users";

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
            if(canBind(providerUrl, userDetails)) {
                return true;
            }
        } catch (Exception ex) {
            Logger.
                getLogger(ActiveDirectoryLoginModule.class.getName()).
                    log(Level.WARNING, "Problem during authentication ", ex);
        }

        throw new FailedLoginException("Your Active Directory Server did not authenticate you.");
    }

    private String constructSearchBase() {
        String userRelativePath = (String) options.get(USERS_OU_LOCATION);
        if( userRelativePath == null ) {
            userRelativePath = DEFAULT_USER_OU;
        }

        StringBuilder searchBaseBuffer = new StringBuilder(userRelativePath);
        searchBaseBuffer.append(", ");
        StringTokenizer tokenizer = new StringTokenizer((String) options.get(DOMAIN_PARAMETERNAME), ".");
        while (tokenizer.hasMoreTokens()) {
            searchBaseBuffer.append("dc=");
            searchBaseBuffer.append(tokenizer.nextToken());
            searchBaseBuffer.append(", ");
        }
        // Remove the last comma.
        searchBaseBuffer.delete(searchBaseBuffer.length() - 2, searchBaseBuffer.length());
        return searchBaseBuffer.toString();
    }

    private boolean canBind(String providerUrl, UserDetails userDetails)
            throws NamingException {
        DirContext context = new InitialDirContext(getNoAuthEnvironment(providerUrl));
        try {
            return canBind(providerUrl, userDetails, context);
        } finally {
            context.close();
        }
    }

    private boolean canBind(String providerUrl, UserDetails userDetails, DirContext context)
            throws NamingException {
        String searchFilter = "(&(objectClass=user)(sAMAccountName=" + userDetails.username + "))";
        Hashtable<String,Object> rebindEnv = getSimpleAuthEnvironment(providerUrl);

        String searchBase = constructSearchBase();
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> matches = context.search( searchBase, searchFilter, searchControls);

        while (matches.hasMore() && !loginOK) {
            SearchResult thisResult = matches.next();
            String dn = thisResult.getName();
            if(canBindToServer(rebindEnv, searchBase, dn, userDetails.password)) {
                return true;
            }
        }
        return false;
    }

	@Override
	public Set<AuthenticationSourceConfigurationOption> getConfigurationOptions() {
    	Set<AuthenticationSourceConfigurationOption> newConfigurationOptions = new TreeSet<>();

    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption(1,
    					"Domain Controller Server Name","ad.domaincontroller",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX, null,"pdc01"));

    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption(2,
    					"Location of users branch relative to the domain", "ad.oulocation",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX, null, "cn=Users"));

    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption(3,
    					"Domain to authenticate", "ad.domain",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX, null,
    					"mydomain.mycompany.com"));

    	addSSLOption(newConfigurationOptions);
    	return newConfigurationOptions;
	}

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
