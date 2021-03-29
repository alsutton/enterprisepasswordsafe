package com.enterprisepasswordsafe.logging;

import com.alsutton.cryptography.Decrypter;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.cryptography.DecrypterFactory;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.LogEntry;
import com.enterprisepasswordsafe.model.persisted.User;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Arrays;

public class LogEntryHashValidator {
    private DAORepository daoRepository;

    public LogEntryHashValidator(DAORepository daoRepository) {
        this.daoRepository = daoRepository;
    }

    public boolean validateTamperstamp(LogEntry logEntry, final User validatingUser)
            throws SQLException, GeneralSecurityException {

        User eventUser = null;
        if (logEntry.getUser() != null) {
            Group adminGroup = daoRepository.getGroupDAO().getAdminGroup(validatingUser);
            eventUser = logEntry.getUser();

            Decrypter decrypter = new DecrypterFactory(adminGroup).decrypterFor(eventUser);
            SecretKey key = eventUser.decryptKey(eventUser::getEncryptedAdminAccessKey, decrypter);
            eventUser.setKey(key);
        }

        byte[] calculatedTamperstamp = new LogEventHasher().createTamperstamp(logEntry);
        byte[] tamperStamp = logEntry.getTamperStamp();
        return Arrays.equals(tamperStamp, calculatedTamperstamp);
    }
}
