package com.enterprisepasswordsafe.engine.logging;

import com.enterprisepasswordsafe.database.TamperproofEventLog;
import com.enterprisepasswordsafe.database.User;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class LogEventHasher {

    private static final String TAMPERSTAMP_HASH_ALGORITHM = "SHA-256";

    public byte[] createTamperstamp(User theUser, TamperproofEventLog event)
            throws GeneralSecurityException {
        String tamperStampData = createTamperstampString(event.getDateTime(),
                event.getEvent(), event.getItemId(), event.getUserId());

        byte[] stampHash = createHash(tamperStampData);
        if (theUser != null) {
            stampHash = theUser.getKeyEncrypter().encrypt(stampHash);
        }
        return stampHash;
    }

    public byte[] createTamperstamp(User theUser, final long datetime, final String event,
                                    final String itemId, final String userId)
            throws GeneralSecurityException {
        String tamperStampData = createTamperstampString(datetime, event, itemId, userId);

        byte[] stampHash = createHash(tamperStampData);
        if (theUser != null) {
            stampHash = theUser.getKeyEncrypter().encrypt(stampHash);
        }
        return stampHash;
    }


    private byte[] createHash(final String value)
            throws NoSuchAlgorithmException {
        MessageDigest digester = MessageDigest.getInstance(TAMPERSTAMP_HASH_ALGORITHM);
        digester.update(value.getBytes());
        return digester.digest();
    }

    private static String createTamperstampString(final long datetime, final String event,
                                                 final String itemId, final String userId) {
        StringBuilder dataToCheck = new StringBuilder();
        dataToCheck.append(datetime);
        dataToCheck.append(event);
        if (itemId != null) {
            dataToCheck.append(itemId);
        }
        if (userId != null) {
            dataToCheck.append(userId);
        }

        return dataToCheck.toString();
    }
}
