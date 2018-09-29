package com.enterprisepasswordsafe.engine.passwords;

import com.enterprisepasswordsafe.engine.database.AccessControl;
import com.enterprisepasswordsafe.engine.database.ConfigurationDAO;
import com.enterprisepasswordsafe.engine.database.ConfigurationOption;
import com.enterprisepasswordsafe.engine.database.Password;
import com.enterprisepasswordsafe.engine.utils.PasswordUtils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Properties;

public class PasswordPropertiesSerializer {
    private static final String AUDIT_PARAMETER = "_audit";
    private static final String HISTORY_RECORDING_PARAMETER = "_historyrecording";
    private static final String RESTRICTION_PARAMETER = "_restriction";
    private static final String RESTRICTED_ACCESS_PARAMETER = "_ra";
    private static final String TYPE_PARAMETER = "_type";

    public void decryptPasswordProperties(final Password password, final byte[] encryptedPasswordProperties,
                                          final AccessControl ac)
            throws IOException, GeneralSecurityException, SQLException {
        Properties props = new Properties();
        PasswordUtils.decrypt(password, ac, encryptedPasswordProperties, props);
        password.setAuditLevel(decodeLoggingLevel(props));
        password.setHistoryStored(decodeStringBoolean(props, HISTORY_RECORDING_PARAMETER));
        password.setRestrictionId(props.getProperty(RESTRICTION_PARAMETER));

        decodeRestrictedAccessSettings(password, props);

        String passwordTypeString = props.getProperty(TYPE_PARAMETER);
        if(passwordTypeString != null) {
            password.setPasswordType(Integer.parseInt(passwordTypeString));
        }
    }


    private AuditingLevel decodeLoggingLevel(Properties passwordProperties)
            throws SQLException {
        String systemAuditState = ConfigurationDAO.getValue( ConfigurationOption.PASSWORD_AUDIT_LEVEL );
        AuditingLevel level = AuditingLevel.fromRepresentation(systemAuditState);
        if (level != AuditingLevel.CREATOR_CHOOSE) {
            return level;
        }

        String passwordAuditingLevel = passwordProperties.getProperty(AUDIT_PARAMETER);
        if (passwordAuditingLevel != null) {
            return AuditingLevel.fromRepresentation(passwordAuditingLevel);
        }

        return AuditingLevel.FULL;
    }

    private void decodeRestrictedAccessSettings(Password password, Properties properties) {
        boolean raEnabled = decodeStringBoolean(properties, RESTRICTED_ACCESS_PARAMETER);
        password.setRaEnabled(raEnabled);
        if(!raEnabled) {
            return;
        }

        password.setRaApprovers(Integer.parseInt(properties.getProperty(RESTRICTED_ACCESS_PARAMETER+"_a")));
        password.setRaBlockers(Integer.parseInt(properties.getProperty(RESTRICTED_ACCESS_PARAMETER+"_b")));
    }

    private boolean decodeStringBoolean(Properties properties, String propertyName) {
        String booleanFlag = properties.getProperty(propertyName);
        if (booleanFlag == null || booleanFlag.isEmpty()) {
            return false;
        }
        return booleanFlag.charAt(0) == 'Y';
    }
}
