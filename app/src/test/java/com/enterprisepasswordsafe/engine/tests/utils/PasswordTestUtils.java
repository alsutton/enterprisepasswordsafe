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

package com.enterprisepasswordsafe.engine.tests.utils;

import com.enterprisepasswordsafe.model.dao.PasswordDAO;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.PasswordAccessControl;
import com.enterprisepasswordsafe.model.persisted.User;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

/**
 * Utility methods supporting password manipulation
 */
public final class PasswordTestUtils {

    /**
     * Do not instantiate
     */

    private PasswordTestUtils() {
        super();
    }

    /**
     * Create a password.
     *
     * @param runId The ID to use for the password to ensure its details are unique.
     *
     * @return The ID of the created password.
     */
    public static String createPassword(final String runId, final User adminUser)
            throws GeneralSecurityException, IOException, SQLException {
        PasswordDAO pDAO = PasswordDAO.getInstance();

        Password newPassword = new Password("u"+runId, "p"+runId, "l"+runId, "n"+runId  );
        PasswordAccessControl uac = pDAO.storeNewPassword(newPassword, adminUser);
        return uac;
    }
}
