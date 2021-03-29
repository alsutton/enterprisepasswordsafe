package com.enterprisepasswordsafe.authentication.jaas;

import java.util.Set;
import java.util.TreeSet;

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

    void addSSLOption(Set<AuthenticationSourceConfigurationOption> configurationOption) {
        Set<AuthenticationSourceConfigurationOptionValue> yesNoOptions = new TreeSet<>();
        yesNoOptions.add(new AuthenticationSourceConfigurationOptionValue("Yes", "Y"));
        yesNoOptions.add(new AuthenticationSourceConfigurationOptionValue("No", "N"));
        configurationOption.add(
                new AuthenticationSourceConfigurationOption( 6, "Connect using SSL",
                        "ad.ldaps", AuthenticationSourceConfigurationOption.RADIO_BOX,
                        yesNoOptions, "N"));


    }
}
