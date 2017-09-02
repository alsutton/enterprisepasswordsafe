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

import com.enterprisepasswordsafe.engine.tests.utils.EmbeddedDatabaseUtils;
import org.junit.BeforeClass;
import org.junit.Test;

import java.sql.SQLException;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

/**
 * Tests for the PasswordRestrictionDAO
 */
public class PasswordRestrictionDAOTests {
    /**
     * The DAO to use for testing.
     */
    private final PasswordRestrictionDAO mPasswordRestrictionDAO = PasswordRestrictionDAO.getInstance();

    @BeforeClass
    public static void setupDatabase() throws Exception {
        EmbeddedDatabaseUtils.initialise();
    }

    @Test
    public void testCreateAndGetById() throws SQLException {
        String runId = Long.toString(System.currentTimeMillis());

        PasswordRestriction createdRestriction = mPasswordRestrictionDAO.create(runId, 0, 0, 0, 0, 0, 0, "", 0);
        PasswordRestriction fetchedRestriction = mPasswordRestrictionDAO.getById(createdRestriction.getId());
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

        PasswordRestriction createdRestriction = new PasswordRestriction(runId, 0, 0, 0, 0, 0, 0, "", 0);
        mPasswordRestrictionDAO.store(createdRestriction);
        PasswordRestriction fetchedRestriction = mPasswordRestrictionDAO.getById(createdRestriction.getId());
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

        PasswordRestriction createdRestriction = new PasswordRestriction(runId, 0, 0, 0, 0, 0, 0, "", 0);
        mPasswordRestrictionDAO.store(createdRestriction);
        PasswordRestriction fetchedRestriction = mPasswordRestrictionDAO.getById(createdRestriction.getId());
        fetchedRestriction.setLifetime(10);
        fetchedRestriction.setMaxLength(9);
        fetchedRestriction.setMinLength(8);
        fetchedRestriction.setMinLower(7);
        fetchedRestriction.setMinNumeric(6);
        fetchedRestriction.setMinSpecial(5);
        fetchedRestriction.setMinUpper(4);
        fetchedRestriction.setName("Updated");
        fetchedRestriction.setSpecialCharacters("!");
        mPasswordRestrictionDAO.update(fetchedRestriction);
        fetchedRestriction = mPasswordRestrictionDAO.getById(createdRestriction.getId());
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

        PasswordRestriction createdRestriction = new PasswordRestriction(runId, 0, 0, 0, 0, 0, 0, "", 0);
        mPasswordRestrictionDAO.store(createdRestriction);
        PasswordRestriction fetchedRestriction = mPasswordRestrictionDAO.getById(createdRestriction.getId());
        assertThat(fetchedRestriction, is(not(nullValue())));
        mPasswordRestrictionDAO.delete(createdRestriction.getId());
        fetchedRestriction = mPasswordRestrictionDAO.getById(createdRestriction.getId());
        assertThat(fetchedRestriction, is(nullValue()));
    }

    @Test
    public void testGetAll() throws SQLException {
        String runId = Long.toString(System.currentTimeMillis());

        PasswordRestriction createdRestriction = new PasswordRestriction(runId, 0, 0, 0, 0, 0, 0, "", 0);
        mPasswordRestrictionDAO.store(createdRestriction);

        boolean found = false;
        for(PasswordRestriction.Summary summary : mPasswordRestrictionDAO.getAll()) {
            if(summary.getId().equals(createdRestriction.getId())
            && summary.getName().equals(runId)) {
                found = true;
                break;
            }
        }

        assertThat(found, is(true));
    }
}
