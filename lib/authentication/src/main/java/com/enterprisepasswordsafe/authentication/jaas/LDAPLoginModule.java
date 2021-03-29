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

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import java.util.Hashtable;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class LDAPLoginModule
        extends BaseLDAPLoginModule
	    implements AuthenticationSourceModule {

    public boolean login() throws LoginException {
        loginOK = false;
        if (callbackHandler == null) {
            throw new LoginException("Callback handler not defined.");
        }

        UserDetails userDetails = getUserDetailsFromCallbacks();
        try {
            Hashtable<String,Object> env = getSimpleAuthEnvironment();

            StringBuilder principal = new StringBuilder();
            principal.append(options.get("prefix"));
            principal.append('=');
            principal.append(userDetails.username);
            principal.append(',');
            principal.append(options.get("base"));
            env.put(Context.SECURITY_PRINCIPAL, principal.toString());
            env.put(Context.SECURITY_CREDENTIALS, userDetails.password);

            DirContext ctx = new InitialDirContext(env);
            ctx.close();

            loginOK = true;
            return true;
        } catch (Exception ex) {
            Logger.getLogger(LDAPSearchAndBindLoginModule.class.getName()).
                    log(Level.WARNING, "Problem during authentication ", ex);
        }

        throw new FailedLoginException("Your LDAP Server did not authenticate you.");
    }

	public Set<AuthenticationSourceConfigurationOption> getConfigurationOptions() {
    	Set<AuthenticationSourceConfigurationOption> newConfigurationOptions = new TreeSet<>();
    	
    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption(1,
    					"Directory URL", "url",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX, null,
    					"ldap://[machine_name]:389/"));

    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption(2,
    					"User Base","base",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX, null,null));

    	newConfigurationOptions.add(new AuthenticationSourceConfigurationOption(3,
    					"Username Prefix", "prefix",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX, null,"cn"));
    	
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
