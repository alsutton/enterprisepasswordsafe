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

import java.util.Set;
import java.util.TreeSet;

/**
 * Dummy class holding the configuration options for 
 */
public class JndiLoginModuleDummy implements AuthenticationSourceModule {

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
    					"User URL",
    					"user.provider.url",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					"ldap://user_ldap_server:389/ou=People,dc=some,dc=com"  
    				)
    		);

    	newConfigurationOptions.add(
    			new AuthenticationSourceConfigurationOption(
    					2,
    					"Group URL",
    					"group.provider.url",
    					AuthenticationSourceConfigurationOption.TEXT_INPUT_BOX,
    					null,
    					"ldap://group_ldap_server:389/ou=Groups,dc=some,dc=com"  
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
		return "";
	}
}
