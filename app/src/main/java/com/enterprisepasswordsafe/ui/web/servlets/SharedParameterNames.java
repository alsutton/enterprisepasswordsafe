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

package com.enterprisepasswordsafe.ui.web.servlets;

import com.enterprisepasswordsafe.authentication.jaas.EPSJAASConfiguration;

public class SharedParameterNames {

    /**
     * Parameter/Attribute name used to store a password ID.
     */

    public static final String PASSWORD_ID_PARAMETER = "id";

    /**
     * The attribute name used to store a password.
     */

    public static final String PASSWORD_ATTRIBUTE = "password";

    /**
     * Atrribute used to store "password on screen" timeout.
     */

    public static final String PASSWORD_TIMEOUT_ATTRIBUTE = "password_timeout";


	public static final String 
		DATABASE_APPLICATION_CONFIGURATION = EPSJAASConfiguration.DATABASE_APPLICATION_CONFIGURATION,
		AD_APPLICATION_CONFIGURATION = EPSJAASConfiguration.AD_APPLICATION_CONFIGURATION,
		AD_NONANON_APPLICATION_CONFIGURATION = EPSJAASConfiguration.AD_NONANON_APPLICATION_CONFIGURATION,
		AD_DOMAIN_APPLICATION_CONFIGURATION = EPSJAASConfiguration.AD_DOMAIN_APPLICATION_CONFIGURATION,
		LDAP_APPLICATION_CONFIGURATION = EPSJAASConfiguration.LDAP_APPLICATION_CONFIGURATION,
		LDAP_SANDB_APPLICATION_CONFIGURATION = EPSJAASConfiguration.LDAP_SANDB_APPLICATION_CONFIGURATION,
		RFC2307_APPLICATION_CONFIGURATION = EPSJAASConfiguration.RFC2307_APPLICATION_CONFIGURATION;
}
