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

package com.enterprisepasswordsafe.engine.database;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.enterprisepasswordsafe.engine.utils.KeyUtils;

/**
 * Object representing the membership of a user in a group.
 */
public class Membership {

    /**
     * The ID of the user involved in the membership.
     */

    private final String userId;

    /**
     * The ID of the group involved in the membership.
     */

    private final String groupId;

    /**
     * The access key for the membership.
     */
    private final SecretKey accessKey;

    /**
     * Creates a new instance of Membership.
     *
     * @param newUserId
     *            The ID of the user this relationship is for.
     * @param newGroupId
     *            The ID of the group this relationship is for.
     * @param newAccessKey
     *            The group access key.
     */
    public Membership(final String newUserId, final String newGroupId,
            final SecretKey newAccessKey) {
        userId = newUserId;
        groupId = newGroupId;
        accessKey = newAccessKey;
    }

    /**
     * Creates a new instance of Membership.
     *
     * @param user
     *            The user for the membership.
     * @param group
     *            The group for the membership.
     */
    public Membership(final User user, final Group group) {
        userId = user.getId();
        groupId = group.getGroupId();
        accessKey = group.getAccessKey();
    }

    /**
     * Creates a new instance of Membership.
     *
     * @param rs
     *            The ResultSet containing information about the membership.
     * @param startIdx
     *            The start index for where the data is stored.
     * @param user
     *            The user the membership is for.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException The user involved in the membership.
     * @throws UnsupportedEncodingException
     */
    public Membership(final ResultSet rs, final int startIdx, final User user)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        int idx = startIdx;
        userId = rs.getString(idx++);
        groupId = rs.getString(idx++);

        byte[] keyBytes = rs.getBytes(idx++);
        if(rs.wasNull()) {
            accessKey = null;
            return;
        }
        accessKey = KeyUtils.decryptSecretKey(keyBytes, user.getKeyDecrypter());
    }

    /**
     * Decrypts some data using the groups access key.
     *
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem during decryption.
     */

    public byte[] decrypt(final byte[] data)
        throws GeneralSecurityException {
        if (data == null) {
            return null;
        }

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, accessKey);

        return cipher.doFinal(data);
    }

    /**
     * Get the ID of the group involved in the membership.
     *
     * @return The ID of the group involved in the membership.
     */

    public String getGroupId() {
        return groupId;
    }

    /**
     * Get the ID of the user involved in this membership.
     *
     * @return The ID of the user involved in this membership.
     */

    public String getUserId() {
        return userId;
    }

    /**
     * Gets the access key for the group involved in this membership.
     *
     * @return The access key.
     */

    public SecretKey getAccessKey() {
        return accessKey;
    }
}
