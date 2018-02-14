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

import com.enterprisepasswordsafe.engine.configuration.JDBCConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.sql.SQLException;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

/**
 * Tests for the PasswordRestrictionDAO
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest(JDBCConfiguration.class)
@PowerMockIgnore("javax.management.*")
public class PasswordRestrictionDAOTests extends EmbeddedDatabaseTestBase {
    @Test
    public void testCreateAndGetById() throws SQLException {
        String runId = Long.toString(System.currentTimeMillis());

        PasswordRestrictionDAO passwordRestrictionDAO = PasswordRestrictionDAO.getInstance();
        PasswordRestriction createdRestriction =
                passwordRestrictionDAO.create(runId, 0, 0, 0, 0, 0, 0, "", 0);
        PasswordRestriction fetchedRestriction =
                passwordRestrictionDAO.getById(createdRestriction.getId());
        assertThat(fetchedRestriction, is(equalTo(createdRestriction)));
        assertThat(fetchedRestriction.getLifetime(), is(0));
        assertThat(fetchedRestriction.getMaxLength(), is(0));
        assertThat(fetchedRestriction.getMinLength(), is(0));
        assertThat(fetchedRestriction.getMinLower(), is(0));
        assertThat(fetchedRestriction.getMinNumeric(), is(0));
        assertThat(fetchedRestriction.getMinSpecial(), is(0));
        assertThat(fetchedRestriction.getMinUpper(), is(0));
        assertThat(fetchedRestriction.getName(), is(equalTo(runId)));
        assertThat(fetchedRestriction.getSpecialCharacters(), is(equalTo("")));
    }

    @Test
    public void testStoreAndGetById() throws SQLException {
        String runId = Long.toString(System.currentTimeMillis());

        PasswordRestrictionDAO passwordRestrictionDAO = PasswordRestrictionDAO.getInstance();
        PasswordRestriction createdRestriction = new PasswordRestriction(runId, 0, 0, 0, 0, 0, 0, "", 0);
        passwordRestrictionDAO.store(createdRestriction);
        PasswordRestriction fetchedRestriction = passwordRestrictionDAO.getById(createdRestriction.getId());
        assertThat(fetchedRestriction, is(equalTo(createdRestriction)));
        assertThat(fetchedRestriction.getLifetime(), is(0));
        assertThat(fetchedRestriction.getMaxLength(), is(0));
        assertThat(fetchedRestriction.getMinLength(), is(0));
        assertThat(fetchedRestriction.getMinLower(), is(0));
        assertThat(fetchedRestriction.getMinNumeric(), is(0));
        assertThat(fetchedRestriction.getMinSpecial(), is(0));
        assertThat(fetchedRestriction.getMinUpper(), is(0));
        assertThat(fetchedRestriction.getName(), is(equalTo(runId)));
        assertThat(fetchedRestriction.getSpecialCharacters(), is(equalTo("")));
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
        assertThat(fetchedRestriction.getLifetime(), is(10));
        assertThat(fetchedRestriction.getMaxLength(), is(9));
        assertThat(fetchedRestriction.getMinLength(), is(8));
        assertThat(fetchedRestriction.getMinLower(), is(7));
        assertThat(fetchedRestriction.getMinNumeric(), is(6));
        assertThat(fetchedRestriction.getMinSpecial(), is(5));
        assertThat(fetchedRestriction.getMinUpper(), is(4));
        assertThat(fetchedRestriction.getName(), is(equalTo("Updated")));
        assertThat(fetchedRestriction.getSpecialCharacters(), is(equalTo("!")));
    }

    @Test
    public void testDelete() throws SQLException {
        String runId = Long.toString(System.currentTimeMillis());

        PasswordRestrictionDAO passwordRestrictionDAO = PasswordRestrictionDAO.getInstance();
        PasswordRestriction createdRestriction = new PasswordRestriction(runId, 0, 0, 0, 0, 0, 0, "", 0);
        passwordRestrictionDAO.store(createdRestriction);
        PasswordRestriction fetchedRestriction = passwordRestrictionDAO.getById(createdRestriction.getId());
        assertThat(fetchedRestriction, is(not(nullValue())));
        passwordRestrictionDAO.delete(createdRestriction.getId());
        fetchedRestriction = passwordRestrictionDAO.getById(createdRestriction.getId());
        assertThat(fetchedRestriction, is(nullValue()));
    }

    @Test
    public void testGetAll() throws SQLException {
        String runId = Long.toString(System.currentTimeMillis());

        PasswordRestrictionDAO passwordRestrictionDAO = PasswordRestrictionDAO.getInstance();
        PasswordRestriction createdRestriction = new PasswordRestriction(runId, 0, 0, 0, 0, 0, 0, "", 0);
        passwordRestrictionDAO.store(createdRestriction);

        boolean found = false;
        for(PasswordRestriction.Summary summary : passwordRestrictionDAO.getAll()) {
            if(summary.getId().equals(createdRestriction.getId())
            && summary.getName().equals(runId)) {
                found = true;
                break;
            }
        }

        assertThat(found, is(true));
    }
}
