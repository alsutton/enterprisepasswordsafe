package com.enterprisepasswordsafe.authentication;

import com.alsutton.cryptography.Encrypter;
import com.alsutton.cryptography.SymmetricKeySupplier;
import com.enterprisepasswordsafe.authentication.jaas.EPSJAASConfiguration;
import com.enterprisepasswordsafe.authentication.jaas.WebLoginCallbackHandler;
import com.enterprisepasswordsafe.logging.LogStore;
import com.enterprisepasswordsafe.model.ConfigurationOptions;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.EntityState;
import com.enterprisepasswordsafe.model.LogEventClass;
import com.enterprisepasswordsafe.model.ReservedUsers;
import com.enterprisepasswordsafe.model.cryptography.EncrypterFactory;
import com.enterprisepasswordsafe.model.persisted.AuthenticationProperty;
import com.enterprisepasswordsafe.model.persisted.AuthenticationSource;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.User;

import javax.crypto.SecretKey;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public final class UserAuthenticator {

    private final DAORepository daoRepository;
    private final LogStore logStore;

    public UserAuthenticator(DAORepository daoRepository, LogStore logstore) {
        this.daoRepository = daoRepository;
        this.logStore = logstore;
    }

    /**
     * Authenticates the user.
     *
     * @param theUser The user to authenticate
     * @param loginPassword The password the user has logged in with.
     *
     * @throws LoginException if the password was incorrect.
     */

    public void authenticateUser(final User theUser, final String loginPassword)
            throws GeneralSecurityException, UnsupportedEncodingException {
        if (theUser == null || theUser.getState() != EntityState.ENABLED) {
            throw new LoginException("User unknown");
        }

        synchronized( theUser.getId().toString().intern() )
        {
            try {
                AuthenticationSource authSource = theUser.getAuthenticationSource();

                EPSJAASConfiguration configuration =
                        new EPSJAASConfiguration(transformPropertyListToMap(authSource.getProperties()));
                javax.security.auth.login.Configuration.setConfiguration(configuration);
                LoginContext loginContext = new LoginContext(authSource.getJaasType(),
                        new WebLoginCallbackHandler(theUser.getName(), loginPassword.toCharArray()));
                loginContext.login();
            } catch(LoginException ex) {
                if(!ReservedUsers.ADMIN.matches(theUser)) {
                    increaseFailedLogins(theUser);
                }
                throw ex;
            }
        }
    }

    private Map<String,String> transformPropertyListToMap(List<AuthenticationProperty> properties) {
        return properties
                .stream()
                .collect(Collectors.toMap(
                        AuthenticationProperty::getName,
                        AuthenticationProperty::getValue,
                        (a, b) -> b,
                        ConcurrentHashMap::new));
    }

    public void increaseFailedLogins( User user )
            throws GeneralSecurityException, UnsupportedEncodingException {
        int loginAttempts = user.getLoginAttempts() + 1;
        user.setLoginAttempts(loginAttempts);

        String maxAttempts =
                daoRepository.getConfigurationDAO().get(ConfigurationOptions.LOGIN_ATTEMPTS);
        int maxAttemptsInt = Integer.parseInt(maxAttempts);
        if( loginAttempts >= maxAttemptsInt ) {
            logStore.log(LogEventClass.USER_MANIPULATION,
                    user, "The user "+ user.getName() +
                            " has been disabled to due too many failed login attempts ("+loginAttempts+").", false );
            user.setState(EntityState.DISABLED);
        }

        daoRepository.getUserDAO().store(user);
    }

    public void updateLoginPassword(final User user, final String newPassword)
            throws GeneralSecurityException {
        // Always rotate the keys for the main admin user password change
        if( ReservedUsers.ADMIN.matches(user) ) {
            Group adminGroup = daoRepository.getGroupDAO().getAdminGroup(user);
            SecretKey accessKey = new SymmetricKeySupplier().generateKey();

            EncrypterFactory encrypterFactory = new EncrypterFactory(accessKey);
            daoRepository
                    .getPasswordAccessControlDAO()
                    .updateEncryptionOnKeys(user, encrypterFactory, user.getUserAccessControls());
            daoRepository
                    .getMembershipDAO()
                    .updateEncryptionOnKeys(user, encrypterFactory);

            user.setKey(accessKey);
            updateAdminKey(user, adminGroup);
        }

        PasswordHasher passwordHasher = new PasswordHasher();
        user.setUserPassword(passwordHasher.createHashWithRandomSalt(newPassword));
        UserPasswordEncryptionHandler upe = new UserPasswordEncryptionHandler(newPassword);
        user.setEncryptedAccessKey(upe.encrypt(user.getKey().getEncoded()));
        user.setPasswordLastChanged(new Date());
        daoRepository.getUserDAO().store(user);
    }

    /**
     * Update the admin key for a user.
     *
     * @param user The user to encrypt the access key for.
     * @param adminGroup The admin group which holds the key to use.
     */

    private void updateAdminKey(final User user, final Group adminGroup) throws GeneralSecurityException {
        Encrypter encrypter = new EncrypterFactory(adminGroup).encrypterFor(user);
        byte[] encryptedKey = user.encryptKey(encrypter);
        user.setEncryptedAdminAccessKey(encryptedKey);
    }
}
