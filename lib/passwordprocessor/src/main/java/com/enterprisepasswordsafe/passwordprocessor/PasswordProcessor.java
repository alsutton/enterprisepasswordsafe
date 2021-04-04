package com.enterprisepasswordsafe.passwordprocessor;

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.PasswordAccessControl;
import com.enterprisepasswordsafe.model.persisted.User;
import com.enterprisepasswordsafe.model.utils.PasswordDecrypter;
import com.enterprisepasswordsafe.passwordprocessor.actions.PasswordAction;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;

public class PasswordProcessor {

    private final DAORepository daoRepository;

    public PasswordProcessor(DAORepository daoRepository) {
        this.daoRepository = daoRepository;
    }

    /**
     * Performs an action on all passwords stored in the database.
     *
     * @param user The user performing the action.
     * @param action The object which will act on each password.
     *
     * @throws PasswordProcessorException Thrown if there was a problem processing the passwords.
     */

    public void processAllPasswords(final User user, final PasswordAction action)
        throws PasswordProcessorException{
        Set<Long> processedPasswords = new HashSet<>();

        Predicate<Password> userPrivilegePredicate = getFilterForUserPriviledges(user);

        try {
            processAllPasswordsWork(action,
                    user.getUserAccessControls(),
                    userPrivilegePredicate,
                    processedPasswords);
            processAllPasswordsWork(action,
                    daoRepository.getPasswordAccessControlDAO().getAllAccessControlsViaGroupMemberships(user),
                    userPrivilegePredicate,
                    processedPasswords);
        } catch (IOException | GeneralSecurityException e) {
            throw new PasswordProcessorException("Internal Error", e);
        }
    }

    private Predicate<Password> getFilterForUserPriviledges(User user) {
        return daoRepository.getMembershipDAO().isAdminUser(user) ? password -> true : new EnabledPasswordFilter();
    }

    /**
     * Performs an action on all passwords stored in the database.
     *
     * @param action The object which will act on each password.
     * @param accessControls The access controls to apply the action via.
     * @param processedPasswords The passwords which have already been processed
     *
     * @throws PasswordProcessorException can be thrown by any action.
     * @throws GeneralSecurityException thrown if there is a problem decrypting a password.
     * @throws IOException thrown if there is a problem decrypting the password properties.
     */

    public void processAllPasswordsWork(final PasswordAction action,
                                        final List<PasswordAccessControl> accessControls,
                                        final Predicate<Password> privilegePredicate,
                                        final Set<Long> processedPasswords)
            throws PasswordProcessorException, GeneralSecurityException, IOException {
        PasswordDecrypter passwordDecrypter = new PasswordDecrypter();

        for(PasswordAccessControl accessControl : accessControls) {
            if(accessControl.getEncryptedReadKey() == null) {
                continue;
            }

            Password password = accessControl.getPassword();
            if (password == null
            ||  !privilegePredicate.test(password)
            ||  processedPasswords.contains(password.getId())) {
                continue;
            }

            passwordDecrypter.decrypt(password, accessControl);
            action.process(password);
            processedPasswords.add(password.getId());
        }
    }

    private static class EnabledPasswordFilter implements Predicate<Password> {
        @Override
        public boolean test(Password password) {
            Boolean state = password.getEnabled();
            return state != null || state;
        }
    }
}
