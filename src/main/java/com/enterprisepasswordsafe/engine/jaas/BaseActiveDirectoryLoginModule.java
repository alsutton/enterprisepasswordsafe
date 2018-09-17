package com.enterprisepasswordsafe.engine.jaas;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.Set;

public abstract class BaseActiveDirectoryLoginModule extends BaseLDAPLoginModule {

    public static final String LDAPS_PARAMETERNAME = "ad.ldaps";

    public boolean abort() {
        // If we didn't log in ignore this module
        if (!loginOK) {
            return false;
        }

        if (commitOK) {
            // If the login was OK, and the commit was OK we need to log out
            // again.
            logout();
        } else {
            // If the commit hasn't happened clear out any stored info
            loginOK = false;
        }

        return true;
    }

    String getBindUrl(String domainController) {
        return getLdapProtocol() + domainController + '/';
    }

    private String getLdapProtocol() {
        String sslFlag = (String) options.get(LDAPS_PARAMETERNAME);
        boolean sslOff = sslFlag == null || sslFlag.charAt(0) == 'N';
        return sslOff ? "ldap://" : "ldaps://";
    }
}
