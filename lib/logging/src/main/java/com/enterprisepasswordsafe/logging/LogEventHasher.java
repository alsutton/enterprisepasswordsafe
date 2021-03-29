package com.enterprisepasswordsafe.logging;

import com.alsutton.cryptography.Encrypter;
import com.enterprisepasswordsafe.model.cryptography.EncrypterFactory;
import com.enterprisepasswordsafe.model.persisted.LogEntry;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.User;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

public class LogEventHasher {

    private static final String TAMPERSTAMP_HASH_ALGORITHM = "SHA-256";

    public byte[] createTamperstamp(LogEntry event)
            throws GeneralSecurityException {
        return createTamperstamp(event.getTimestamp(),
                event.getEvent(), event.getItem(), event.getUser());
    }

    public byte[] createTamperstamp(final Date datetime, final String event,
                                    final Password item, final User user)
            throws GeneralSecurityException {
        String tamperStampData = createTamperstampString(datetime, event, item, user);

        byte[] stampHash = createHash(tamperStampData);
        if (user != null) {
            Encrypter encrypter = new EncrypterFactory(user).encrypterFor(user);
            stampHash = encrypter.apply(stampHash);
        }
        return stampHash;
    }


    private byte[] createHash(final String value)
            throws NoSuchAlgorithmException {
        MessageDigest digester = MessageDigest.getInstance(TAMPERSTAMP_HASH_ALGORITHM);
        digester.update(value.getBytes(StandardCharsets.UTF_8));
        return digester.digest();
    }

    private static String createTamperstampString(final Date datetime, final String event,
                                                 final Password item, final User user) {
        StringBuilder dataToCheck = new StringBuilder();
        dataToCheck.append(datetime);
        dataToCheck.append(event);
        if (item != null) {
            dataToCheck.append(item.getId());
        }
        if (user != null) {
            dataToCheck.append(user.getId());
        }

        return dataToCheck.toString();
    }
}
