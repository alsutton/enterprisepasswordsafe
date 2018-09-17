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
import javax.naming.NamingException;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.Hashtable;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class ActiveDirectoryDomainLoginModule
	extends BaseActiveDirectoryLoginModule
	implements LoginModule, AuthenticationSourceModule {

    public static final String AD_DOMAIN = "ad.domain";

    public static final String DOMAIN_CONTROLLER_PARAMETERNAME = "ad.domaincontroller";

    @Override
	public boolean login() throws LoginException {
        loginOK = false;

        if (callbackHandler == null) {
            throw new LoginException("Callback handler not defined.");
        }

        UserDetails userDetails = getUserDetailsFromCallbacks();
        StringTokenizer domainControllers = new StringTokenizer((String)options.get(DOMAIN_CONTROLLER_PARAMETERNAME), ";");

        final Control[] contextControls = { new LDAPADControl() };
        while( domainControllers.hasMoreTokens() ) {
        	try {
				Hashtable<String, Object> bindEnvironment = getBindingEnvironment(userDetails, domainControllers.nextToken());

	            LdapContext context = null;
	            try {
		            context = new InitialLdapContext(bindEnvironment, contextControls);
		            loginOK = true;
	            } catch (NamingException e) {
	            	loginOK = false;
	            } finally {
	            	if( context != null ) {
	            		context.close();
	            	}
	            }

	            return true;
	        } catch (Exception ex) {
	            Logger.getLogger(ActiveDirectoryDomainLoginModule.class.getName()).
	                    log(Level.WARNING, "Problem during authentication ", ex);
	        }
    	}

        throw new FailedLoginException("Your Active Directory Server did not authenticate you.");
    }

	private Hashtable<String,Object> getBindingEnvironment(UserDetails userDetails, String domainController) {
		Hashtable<String,Object> env = new Hashtable<>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.PROVIDER_URL, getProviderUrl(domainController));
		env.put(Context.SECURITY_PRINCIPAL, getUserDN(userDetails));
		env.put(Context.SECURITY_CREDENTIALS, userDetails.password);
		return env;
	}

	private String getProviderUrl(String domainController) {
    	StringBuilder providerUrlBuffer = new StringBuilder();
    	providerUrlBuffer.append(getBindUrl(domainController));
		if(options.get(AD_DOMAIN) != null ) {
			StringTokenizer strtok = new StringTokenizer(((String)options.get(AD_DOMAIN)),".");
			while(strtok.hasMoreTokens()) {
				providerUrlBuffer.append("dc=");
				providerUrlBuffer.append(strtok.nextToken());
				providerUrlBuffer.append(',');
			}
			providerUrlBuffer.deleteCharAt(providerUrlBuffer.length()-1);
		}
		return providerUrlBuffer.toString();
	}

	private String getUserDN(UserDetails userDetails) {
		StringBuilder userBuilder = new StringBuilder();
		userBuilder.append(userDetails.username);
		userBuilder.append('@');
		userBuilder.append(options.get(AD_DOMAIN));
		return userBuilder.toString();
	}


	@Override
	public Set<AuthenticationSourceConfigurationOption> getConfigurationOptions() {
    	Set<AuthenticationSourceConfigurationOption> newConfigurationOptions = new TreeSet<>();
    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption( 1, "Domain",
						"ad.domain", AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,"DOMAIN"));
    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption(
    					2, "Domain Controllers", "ad.domaincontroller",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,null,"pdc01;bdc01"));

    	Set<AuthenticationSourceConfigurationOptionValue> yesNoOptions = new TreeSet<>();
    	yesNoOptions.add(new AuthenticationSourceConfigurationOptionValue("Yes", "Y"));
    	yesNoOptions.add(new AuthenticationSourceConfigurationOptionValue("No", "N"));
    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption(
    			3, "Connect using SSL", "ad.ldaps",
				AuthenticationSourceConfigurationOption.RADIO_BOX, yesNoOptions,"N"));

    	return newConfigurationOptions;
	}

	@Override
	public String getConfigurationNotes() {
		return "Warning: Connecting over SSL may not work if your Active Directory Server is using "+
			   "an SSL Certificate from a certificate authority which is not known by your Java "+
			   "Virtual Machine.";
	}


	private static class LDAPADControl implements Control {
		@Override
		public byte[] getEncodedValue() {
	        	return null;
		}
	  	@Override
		public String getID() {
			return "1.2.840.113556.1.4.1781";
		}
	 	@Override
		public boolean isCritical() {
			return true;
		}
	}
}
