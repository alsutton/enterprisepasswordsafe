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

package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.engine.tests.utils.PasswordTestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.List;
import java.util.Set;

/**
 * Test cases for the PasswordDAO
 */
public class PasswordDAOTests extends EmbeddedDatabaseTestBase {

    @Test
    public void testStoreNewPassword()
            throws GeneralSecurityException, IOException, SQLException {
        String runId = Long.toString(System.currentTimeMillis());
        String passwordId = PasswordTestUtils.createPassword(runId, getAdminUser());

        User adminUser = getAdminUser();
        Password retrieved = PasswordDAO.getInstance().getById(adminUser, passwordId);
        Assertions.assertEquals("u" + runId, retrieved.getUsername());
        Assertions.assertEquals("p" + runId, retrieved.getPassword());
        Assertions.assertEquals("l" + runId, retrieved.getLocation());
        Assertions.assertEquals("n" + runId, retrieved.getNotes());
    }

    @Test
    public void testPerformRawAPISearch()
            throws GeneralSecurityException, IOException, SQLException {
        String runId = Long.toString(System.currentTimeMillis());
        User adminUser = getAdminUser();
        String passwordId = PasswordTestUtils.createPassword(runId, adminUser);
        Set<String> ids = PasswordDAO.getInstance().performRawAPISearch(adminUser, "u" + runId, "l" + runId);
        Assertions.assertFalse(ids.isEmpty());
        Assertions.assertTrue(ids.contains(passwordId));
    }

    @Test
    public void testGetPasswordsRestrictionAppliesTo()
            throws SQLException, GeneralSecurityException, IOException {
        String runId = Long.toString(System.currentTimeMillis());
        String passwordId = PasswordTestUtils.createPassword(runId, getAdminUser());

        PasswordRestrictionDAO prDAO = PasswordRestrictionDAO.getInstance();
        PasswordRestriction createdRestriction = new PasswordRestriction("pr_"+runId, 0, 0, 0, 0, 0, 0, "", 0);
        prDAO.store(createdRestriction);

        PasswordDAO pDAO = PasswordDAO.getInstance();
        User adminUser = getAdminUser();
        Password password = pDAO.getById(adminUser, passwordId);
        password.setRestrictionId(createdRestriction.getId());
        pDAO.update(password, adminUser);

        List<Password> passwords= pDAO.getPasswordsRestrictionAppliesTo(createdRestriction.getId());
        Assertions.assertFalse(passwords.isEmpty());

        boolean found = false;
        for(Password thisPassword: passwords) {
            if(thisPassword.getId().equals(passwordId)) {
                found = true;
                break;
            }
        }
        Assertions.assertTrue(found);
    }
}
