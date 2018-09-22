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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;

public class PasswordRestrictionDAOTests extends EmbeddedDatabaseTestBase {
    @Test
    public void testCreateAndGetById() throws SQLException {
        String runId = Long.toString(System.currentTimeMillis());

        PasswordRestrictionDAO passwordRestrictionDAO = PasswordRestrictionDAO.getInstance();
        PasswordRestriction createdRestriction =
                passwordRestrictionDAO.create(runId, 0, 0, 0, 0, 0, 0, "", 0);
        PasswordRestriction fetchedRestriction =
                passwordRestrictionDAO.getById(createdRestriction.getId());
        Assertions.assertEquals(createdRestriction, fetchedRestriction);
        Assertions.assertEquals(0, fetchedRestriction.getLifetime());
        Assertions.assertEquals(0, fetchedRestriction.getMaxLength());
        Assertions.assertEquals(0, fetchedRestriction.getMinLength());
        Assertions.assertEquals(0, fetchedRestriction.getMinLower());
        Assertions.assertEquals(0, fetchedRestriction.getMinNumeric());
        Assertions.assertEquals(0, fetchedRestriction.getMinSpecial());
        Assertions.assertEquals(0, fetchedRestriction.getMinUpper());
        Assertions.assertEquals(runId, fetchedRestriction.getName());
        Assertions.assertEquals("", fetchedRestriction.getSpecialCharacters());
    }

    @Test
    public void testStoreAndGetById() throws SQLException {
        String runId = Long.toString(System.currentTimeMillis());

        PasswordRestrictionDAO passwordRestrictionDAO = PasswordRestrictionDAO.getInstance();
        PasswordRestriction createdRestriction = new PasswordRestriction(runId, 0, 0, 0, 0, 0, 0, "", 0);
        passwordRestrictionDAO.store(createdRestriction);
        PasswordRestriction fetchedRestriction = passwordRestrictionDAO.getById(createdRestriction.getId());
        Assertions.assertEquals(0, fetchedRestriction.getLifetime());
        Assertions.assertEquals(0, fetchedRestriction.getMaxLength());
        Assertions.assertEquals(0, fetchedRestriction.getMinLength());
        Assertions.assertEquals(0, fetchedRestriction.getMinLower());
        Assertions.assertEquals(0, fetchedRestriction.getMinNumeric());
        Assertions.assertEquals(0, fetchedRestriction.getMinSpecial());
        Assertions.assertEquals(0, fetchedRestriction.getMinUpper());
        Assertions.assertEquals(runId, fetchedRestriction.getName());
        Assertions.assertEquals("", fetchedRestriction.getSpecialCharacters());
    }

    @Test
    public void testUpdate() throws SQLException {
        String runId = Long.toString(System.currentTimeMillis());

        PasswordRestrictionDAO passwordRestrictionDAO = PasswordRestrictionDAO.getInstance();
        PasswordRestriction createdRestriction = new PasswordRestriction(runId, 0, 0, 0, 0, 0, 0, "", 0);
        passwordRestrictionDAO.store(createdRestriction);
        PasswordRestriction fetchedRestriction = passwordRestrictionDAO.getById(createdRestriction.getId());
        fetchedRestriction.setLifetime(10);
        fetchedRestriction.setMaxLength(9);
        fetchedRestriction.setMinLength(8);
        fetchedRestriction.setMinLower(7);
        fetchedRestriction.setMinNumeric(6);
        fetchedRestriction.setMinSpecial(5);
        fetchedRestriction.setMinUpper(4);
        fetchedRestriction.setName("Updated");
        fetchedRestriction.setSpecialCharacters("!");
        passwordRestrictionDAO.update(fetchedRestriction);
        fetchedRestriction = passwordRestrictionDAO.getById(createdRestriction.getId());
        Assertions.assertEquals(10, fetchedRestriction.getLifetime());
        Assertions.assertEquals(9, fetchedRestriction.getMaxLength());
        Assertions.assertEquals(8, fetchedRestriction.getMinLength());
        Assertions.assertEquals(7, fetchedRestriction.getMinLower());
        Assertions.assertEquals(6, fetchedRestriction.getMinNumeric());
        Assertions.assertEquals(5, fetchedRestriction.getMinSpecial());
        Assertions.assertEquals(4, fetchedRestriction.getMinUpper());
        Assertions.assertEquals("Updated", fetchedRestriction.getName());
        Assertions.assertEquals("!", fetchedRestriction.getSpecialCharacters());
    }

    @Test
    public void testDelete() throws SQLException {
        String runId = Long.toString(System.currentTimeMillis());

        PasswordRestrictionDAO passwordRestrictionDAO = PasswordRestrictionDAO.getInstance();
        PasswordRestriction createdRestriction = new PasswordRestriction(runId, 0, 0, 0, 0, 0, 0, "", 0);
        passwordRestrictionDAO.store(createdRestriction);
        PasswordRestriction fetchedRestriction = passwordRestrictionDAO.getById(createdRestriction.getId());
        Assertions.assertNotNull(fetchedRestriction);
        passwordRestrictionDAO.delete(createdRestriction.getId());
        fetchedRestriction = passwordRestrictionDAO.getById(createdRestriction.getId());
        Assertions.assertNull(fetchedRestriction);
    }

    @Test
    public void testGetAll() throws SQLException {
        String runId = Long.toString(System.currentTimeMillis());

        PasswordRestrictionDAO passwordRestrictionDAO = PasswordRestrictionDAO.getInstance();
        PasswordRestriction createdRestriction = new PasswordRestriction(runId, 0, 0, 0, 0, 0, 0, "", 0);
        passwordRestrictionDAO.store(createdRestriction);

        boolean found = false;
        for(PasswordRestriction.Summary summary : passwordRestrictionDAO.getAll()) {
            if(summary.id.equals(createdRestriction.getId())
            && summary.name.equals(runId)) {
                found = true;
                break;
            }
        }
        Assertions.assertTrue(found);
    }
}
