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

import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Data access object for the user access control.
 */
public class PasswordRestrictionDAO
	implements ExternalInterface {

    /**
     * The SQL statement to get the restriction for a given ID.
     */

    private static final String GET_SQL =
            "SELECT restriction_id, " +
            "		name, " +
            "		min_numeric, " +
            "		min_lower, " +
            "		min_upper, " +
            "		min_special, " +
            "		min_length, " +
            "		special, " +
            "		lifetime, " +
            "		max_length " +
            "  FROM password_restrictions " +
            " WHERE restriction_id = ? ";

    /**
     * The SQL statement to insert a restrictions.
     */

    private static final String INSERT_SQL =
            "INSERT INTO password_restrictions( " +
            " 				restriction_id, " +
            "				name, "+
            "				min_numeric, "+
            "				min_lower, "+
            "				min_upper, "+
            "				min_special, "+
            "				min_length, "+
            "				max_length, "+
            "				special, " +
            "				lifetime "+
            "			) VALUES (       "+
            "				?, "+
            "				?, "+
            "				?, "+
            "				?, "+
            "				?, "+
            "				?, "+
            "				?, "+
            "				?, "+
            "				?, "+
            "				? "+
            "			)";

    /**
     * The SQL statement to update a restrictions.
     */

    private static final String UPDATE_SQL =
            "UPDATE password_restrictions " +
            "	SET	name = ?, "+
            "		min_numeric = ?, "+
            "		min_lower = ?, "+
            "		min_upper = ?, "+
            "		min_special = ?, "+
            "		min_length = ?, "+
            "		max_length = ?, "+
            "		special = ?, "+
            "		lifetime = ? " +
            " WHERE restriction_id = ?";

    /**
     * The SQL statement to summaries of all of the restrictions.
     */

    private static final String GET_ALL_SUMMARIES_SQL =
              "   SELECT restriction_id, name "
            + "     FROM password_restrictions "
            + " ORDER BY name";

    /**
     * SQL to delete the details of a restriction from the database
     */

    private static final String DELETE_SQL =
           "DELETE FROM password_restrictions "
         + "      WHERE restriction_id = ? ";

	/**
	 * Private constructor to prevent instantiation
	 */

	private PasswordRestrictionDAO() {
		super();
	}

	/**
	 * Create a password restriction.
	 */

	public PasswordRestriction create(final String name, final int minLower,
    		final int minUpper, final int minNumeric, final int minSpecial,
    		final int minLength, final int maxLength, final String special,
    		final int lifetime)
		throws SQLException {
		PasswordRestriction newRestriction = new PasswordRestriction(
					name, minLower, minUpper, minNumeric, minSpecial,
					minLength, maxLength, special, lifetime
				);
		store(newRestriction);
		return newRestriction;
	}

    /**
     * Store a PasswordRestriction.
     *
     * @param restriction The restriction to store.
     *
     * @throws SQLException Thrown if there is a problem talking to the database.
     */

    public void store(PasswordRestriction restriction)
            throws SQLException {
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(INSERT_SQL);
        try {
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
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }


    /**
     * Update a PasswordRestriction
     *
     * @param restriction The restriction to update.
     *
     * @throws SQLException Thrown if there is a problem talking to the database.
     */

    public void update(PasswordRestriction restriction)
            throws SQLException {
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_SQL);
        try {
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
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Delete a PasswordRestriction.
     *
     * @param id The ID of the restriction to get.
     *
     * @throws SQLException Thrown if there was a problem talking to the database.
     */

    public void delete(final String id)
            throws SQLException {
    	PreparedStatement deleteStatement = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL);
        try {
            deleteStatement.setString(1, id);
            deleteStatement.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(deleteStatement);
        }
    }

    /**
     * Gets a specific PasswordRestriction.
     *
     * @param restrictionId The ID of the restriction to get.
     *
     * @return The requested PasswordRestriction, or null if it doesn't exist.
     *
     * @throws SQLException Thrown if there is problem talking to the database.
     */

    public PasswordRestriction getById(final String restrictionId)
            throws SQLException {
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SQL);
        ResultSet rs = null;
        try {
            ps.setString(1, restrictionId);
            ps.setMaxRows(1);

            rs = ps.executeQuery();
            if (rs.next()) {
                return new PasswordRestriction(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(rs);
            DatabaseConnectionUtils.close(ps);
        }

        return null;
    }

    /**
     * Gets a List of summaries of all the PasswordRestrictions.
     *
     * @return A java.util.List of restrictions
     *
     * @throws SQLException Thrown if there is problem talking to the database.
     */

    public List<PasswordRestriction.Summary> getAll()
            throws SQLException {
    	List<PasswordRestriction.Summary> restrictions = new ArrayList<PasswordRestriction.Summary>();
    	Statement stmt = BOMFactory.getCurrentConntection().createStatement();
        ResultSet rs = null;
        try {
            rs = stmt.executeQuery(GET_ALL_SUMMARIES_SQL);
            while(rs.next()) {
                restrictions.add(
                		new PasswordRestriction.Summary(
                					rs.getString(1),
                					rs.getString(2)
                				)
            		);
            }
        } finally {
            DatabaseConnectionUtils.close(rs);
            DatabaseConnectionUtils.close(stmt);
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
