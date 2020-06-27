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

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class PasswordRestrictionDAO {

    private static final String GET_SQL =
            "SELECT restriction_id, name, min_numeric, min_lower, min_upper, " +
            "		min_special, min_length, special, lifetime, max_length " +
            "  FROM password_restrictions WHERE restriction_id = ? ";

    private static final String INSERT_SQL =
            "INSERT INTO password_restrictions( restriction_id, name, min_numeric, min_lower, min_upper, "+
            "				min_special, min_length, max_length, special, lifetime ) VALUES ( "+
            "				?, ?, ?, ?, ?, ?, ?, ?, ?, ? )";

    private static final String UPDATE_SQL =
            "UPDATE password_restrictions SET name = ?, min_numeric = ?, min_lower = ?, min_upper = ?, "+
            "		min_special = ?, min_length = ?, max_length = ?, special = ?, lifetime = ? " +
            " WHERE restriction_id = ?";

    private static final String GET_ALL_SUMMARIES_SQL =
              "SELECT restriction_id, name FROM password_restrictions ORDER BY name";

    private static final String DELETE_SQL =
           "DELETE FROM password_restrictions WHERE restriction_id = ? ";

	private PasswordRestrictionDAO() {
		super();
	}

	public PasswordRestriction create(final String name, final int minLower,
    		final int minUpper, final int minNumeric, final int minSpecial,
    		final int minLength, final int maxLength, final String special,
    		final int lifetime)
		throws SQLException {
		PasswordRestriction newRestriction = new PasswordRestriction(
					name, minLower, minUpper, minNumeric, minSpecial,
					minLength, maxLength, special, lifetime);
		store(newRestriction);
		return newRestriction;
	}

    public void store(PasswordRestriction restriction)
            throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(INSERT_SQL)) {
            int idx = 1;
            ps.setString( idx++, restriction.getId());
            ps.setString( idx++, restriction.getName());
            ps.setInt   ( idx++, restriction.getMinNumeric());
            ps.setInt   ( idx++, restriction.getMinLower());
            ps.setInt   ( idx++, restriction.getMinUpper());
            ps.setInt   ( idx++, restriction.getMinSpecial());
            ps.setInt   ( idx++, restriction.getMinLength());
            ps.setInt   ( idx++, restriction.getMaxLength());
            ps.setString( idx++, restriction.getSpecialCharacters());
            ps.setInt   ( idx, restriction.getLifetime());
            ps.executeUpdate();
        }
    }

    public void update(PasswordRestriction restriction)
            throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_SQL)) {
            int idx = 1;
            ps.setString( idx++, restriction.getName() );
            ps.setInt   ( idx++, restriction.getMinNumeric() );
            ps.setInt   ( idx++, restriction.getMinLower() );
            ps.setInt   ( idx++, restriction.getMinUpper() );
            ps.setInt   ( idx++, restriction.getMinSpecial() );
            ps.setInt   ( idx++, restriction.getMinLength() );
            ps.setInt   ( idx++, restriction.getMaxLength() );
            ps.setString( idx++, restriction.getSpecialCharacters() );
            ps.setInt   ( idx++, restriction.getLifetime() );
            ps.setString( idx++, restriction.getId() );
            ps.executeUpdate();
        }
    }

    public void delete(final String id)
            throws SQLException {
        try(PreparedStatement deleteStatement = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL)) {
            deleteStatement.setString(1, id);
            deleteStatement.executeUpdate();
        }
    }

    public PasswordRestriction getById(final String restrictionId)
            throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SQL)) {
            ps.setString(1, restrictionId);
            ps.setMaxRows(1);
            try(ResultSet rs = ps.executeQuery()) {
                return rs.next() ? new PasswordRestriction(rs) : null;
            }
        }
    }

    public List<PasswordRestriction.Summary> getAll()
            throws SQLException {
    	List<PasswordRestriction.Summary> restrictions = new ArrayList<PasswordRestriction.Summary>();
        try(Statement stmt = BOMFactory.getCurrentConntection().createStatement()) {
            try(ResultSet rs = stmt.executeQuery(GET_ALL_SUMMARIES_SQL)) {
                while (rs.next()) {
                    restrictions.add(
                            new PasswordRestriction.Summary(rs.getString(1), rs.getString(2)));
                }
            }
        }

        return restrictions;
    }

    private static final class InstanceHolder {
        private static final PasswordRestrictionDAO INSTANCE = new PasswordRestrictionDAO();
    }

    public static PasswordRestrictionDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
