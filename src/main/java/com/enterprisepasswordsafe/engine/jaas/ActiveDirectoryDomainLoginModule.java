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

import java.security.Principal;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * JAAS module for handling logging in a user.
 */
public final class ActiveDirectoryDomainLoginModule
	extends BaseActiveDirectoryLoginModule
	implements LoginModule, AuthenticationSourceModule {

    /**
     * The parameter name for the domain to log the user in with.
     */

    public static final String AD_DOMAIN = "ad.domain";

    /**
     * The parameter name in the options for the LDAP provider base.
     */

    public static final String LDAPS_PARAMETERNAME = "ad.ldaps";

    /**
     * The parameter name in the options for the LDAP provider base.
     */

    public static final String DOMAIN_CONTROLLER_PARAMETERNAME = "ad.domaincontroller";

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
        } catch (Exception e) {
            throw new LoginException(e.getMessage());
        }

        String username = nameCallback.getName();
        if( username == null || username.length() == 0) {
        	throw new FailedLoginException("You must enter a username.");
        }

        char[] passwordChars = passwordCallback.getPassword();
        if( passwordChars == null || passwordChars.length == 0) {
        	throw new FailedLoginException("You must enter a password.");
        }
        String password = new String(passwordCallback.getPassword());

        String sslFlag = (String) options.get(LDAPS_PARAMETERNAME);
        boolean sslOff = sslFlag == null || sslFlag.charAt(0) == 'N';
        String ldapProtocol;
        if(sslOff) {
        	ldapProtocol="ldap://";
        } else {
        	ldapProtocol="ldaps://";
        }

        StringTokenizer domainControllers =
        	new StringTokenizer((String)options.get(DOMAIN_CONTROLLER_PARAMETERNAME), ";");
        StringBuilder providerUrlBuffer = new StringBuilder();
        StringBuilder testUserBuffer = new StringBuilder();
        Hashtable<String,String> env = new Hashtable<String,String>();

        final Control[] contextControls = { new LDAPADControl() };
        while( domainControllers.hasMoreTokens() ) {
        	try {
        		providerUrlBuffer.delete(0, providerUrlBuffer.length());
		        providerUrlBuffer.append(ldapProtocol);
		        providerUrlBuffer.append(domainControllers.nextToken().trim());
		        providerUrlBuffer.append('/');
		        if(options.get(AD_DOMAIN) != null ) {
		        	StringTokenizer strtok = new StringTokenizer(((String)options.get(AD_DOMAIN)),".");
		        	while(strtok.hasMoreTokens()) {
		        		providerUrlBuffer.append("dc=");
		        		providerUrlBuffer.append(strtok.nextToken());
		        		providerUrlBuffer.append(',');
		        	}
		        	providerUrlBuffer.deleteCharAt(providerUrlBuffer.length()-1);
		        }
		        String providerUrl = providerUrlBuffer.toString();

		        testUserBuffer.delete(0, testUserBuffer.length());
		        testUserBuffer.append(username);
		        testUserBuffer.append('@');
		        testUserBuffer.append(options.get(AD_DOMAIN));
		        String testUser = testUserBuffer.toString();

	            env.clear();
	            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
	            env.put(Context.SECURITY_AUTHENTICATION, "simple");
	            env.put(Context.PROVIDER_URL, providerUrl);
	            env.put(Context.SECURITY_PRINCIPAL, testUser);
	            env.put(Context.SECURITY_CREDENTIALS, password);
	            LdapContext context = null;
	            try {
		            context = new InitialLdapContext(env, contextControls);
		            loginOK = true;
	            } catch (AuthenticationException ae) {
		            loginOK = false;
	            } catch (NamingException e) {
	            	loginOK = false;
	            } finally {
	            	if( context != null ) {
	            		context.close();
	            	}
	            }

	            return true;
	        } catch (Exception ex) {
	            Logger.
	                getLogger(ActiveDirectoryDomainLoginModule.class.getName()).
	                    log(Level.WARNING, "Problem during authentication ", ex);
	        }
    	}

        throw new FailedLoginException("Your Active Directory Server did not authenticate you.");
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
    					"Domain",
    					"ad.domain",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					"DOMAIN"
    				)
    		);

    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					2,
    					"Domain Controllers",
    					"ad.domaincontroller",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					"pdc01;bdc01"
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
    					3,
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
			   "Virtual Machine.";
	}


	private static class LDAPADControl implements Control {
		/**
		 * SerialID for the class.
		 */
		private static final long serialVersionUID = 1021417791170268311L;

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
