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

import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Data access object for the user access control.
 */

public class AuthenticationSourceDAO {

    /**
     * The SQL to get all the properties associated with a authorisation source.
     */

    private static final String GET_PROPERTIES_SQL =
        "SELECT param_name, param_value "
        + "FROM auth_sources "
        + "WHERE  source_id = ?";

    /**
     * The SQL to get all the properties associated with a authorisation source.
     */

    private static final String EXISTS_BY_NAME_SQL =
        "SELECT source_id "
        + "FROM auth_sources "
        + "WHERE param_name = '"+AuthenticationSource.NAME_PARAMETER+"' "
        + "  AND param_value = ?";

    /**
     * The SQL to get all sources.
     */

    private static final String GET_ALL =
        "SELECT source_id, param_name, param_value "
        + "FROM auth_sources "
        + "ORDER BY source_id";

    /**
     * The SQL to store a parameter about an authentication source.
     */

    private static final String STORE_SQL =
        "INSERT INTO auth_sources( source_id, param_name, param_value ) "
        + "                VALUES(         ?,          ?,           ? )";

    /**
     * The SQL to store a parameter about an authentication source.
     */

    private static final String UPDATE_SQL =
        "UPDATE auth_sources"
        + " SET param_value = ? "
        + " WHERE source_id = ? and param_name = ?";

    /**
     * SQL to get the the users who are using this authentication source.
     */

    private static final String GET_USERNAMES_SQL =
          "SELECT appusers.user_name"
        + "  FROM application_users appusers"
        + " WHERE appusers.auth_source = ? "
        + "  AND disabled <> '"+User.DELETED_VALUE+"'";

    /**
     * The SQL to delete this authentication source.
     */

    private static final String DELETE_SQL = "DELETE FROM auth_sources WHERE source_id = ? ";

	/**
	 * Private constructor to prevent instantiation
	 */

	private AuthenticationSourceDAO() {
		super();
	}

	/**
	 * Creates a new authentication source.
	 */

	public AuthenticationSource create(final String name, final String jaasType,
            final Map<String,String> properties)
		throws SQLException, GeneralSecurityException {
		if( existsByName(name) )  {
			throw new GeneralSecurityException("A source with that name already exists");
		}
		AuthenticationSource as = new AuthenticationSource(name, jaasType, properties);
		store(as);
		return as;
	}

    /**
     * Retrieves the authentication source for a specific name.
     *
     * @param sourceId The ID of the source to retrieve.
     *
     * @return The authentication source.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public AuthenticationSource getById(final String sourceId)
            throws SQLException {
        if (sourceId == null || sourceId.equals(AuthenticationSource.DEFAULT_SOURCE_ID)) {
            return AuthenticationSource.DEFAULT_SOURCE;
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_PROPERTIES_SQL)) {
            ps.setString(1, sourceId);
            try(ResultSet rs = ps.executeQuery()) {
                Map<String, String> props = new HashMap<>();
                while (rs.next()) {
                    String key = rs.getString(1);
                    String value = rs.getString(2);
                    if (value != null) {
                        props.put(key, value);
                    }
                }

                if (props.size() == 0) {
                    return null;
                }

                return new AuthenticationSource(sourceId, props);
            }
        }
    }

    /**
     * Retrieves the authentication source for a specific name.
     *
     * @param sourceName the name of the source to get,
     *
     * @return The authentication source.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public boolean existsByName(final String sourceName)
            throws SQLException {
        if (sourceName == null
        ||  sourceName.equals(AuthenticationSource.DEFAULT_SOURCE.getName())) {
            return true;
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(EXISTS_BY_NAME_SQL)) {
            ps.setString(1, sourceName);
            try(ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /**
     * Stores this authentication source in the database.
     *
     * @param source The source to store.
     *
     * @throws SQLException If there is a problem accessing the database.
     */

    public void store(final AuthenticationSource source)
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(STORE_SQL)) {
            addParameterForStore(ps, source,
            		AuthenticationSource.NAME_PARAMETER, source.getName());
            addParameterForStore(ps, source,
            		AuthenticationSource.JAAS_TYPE_PARAMETER, source.getJaasType());
            for(Map.Entry<String,String> thisEntry : source.getProperties().entrySet()) {
                addParameterForStore( ps, source, thisEntry.getKey(), thisEntry.getValue() );
            }

            ps.executeBatch();
        }
    }

    /**
     * Stores a parameter in the prepared statement batch.
     *
     * @param ps The prepared statement used to store the data.
     * @param propertyName The parameter name.
     * @param value The parameter value.
     *
     * @throws SQLException thrown if there is a problem storing the data.
     */

    private void addParameterForStore(final PreparedStatement ps,
    		final AuthenticationSource source, final String propertyName,
            final String value)
        throws SQLException {
        int idx = 1;
        ps.setString(idx++, source.getSourceId());
        ps.setString(idx++, propertyName);
        ps.setString(idx, value);
        ps.addBatch();
    }

    /**
     * Stores this authentication source in the database.
     *
     * @param source The source to update.
     *
     * @throws SQLException If there is a problem accessing the database.
     */

    public void update(final AuthenticationSource source)
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_SQL)) {
            addParameterForUpdate(ps, source,
            		AuthenticationSource.NAME_PARAMETER, source.getName());
            addParameterForUpdate(ps, source,
            		AuthenticationSource.JAAS_TYPE_PARAMETER, source.getJaasType());
            for(Map.Entry<String,String> thisEntry : source.getProperties().entrySet()) {
                addParameterForUpdate( ps, source, thisEntry.getKey(), thisEntry.getValue() );
            }

            ps.executeBatch();
        }
    }

    /**
     * Stores a parameter in the prepared statement batch.
     *
     * @param ps The prepared statement to use to store the data.
     * @param propertyName The parameter name.
     * @param value The parameter value.
     *
     * @throws SQLException Thrown if there is a problem storing the data.
     */

    private void addParameterForUpdate(final PreparedStatement ps,
            final AuthenticationSource source, final String propertyName,
            final String value)
        throws SQLException {
        int idx = 1;
        ps.setString(idx++, value);
        ps.setString(idx++, source.getSourceId());
        ps.setString(idx, propertyName);
        ps.addBatch();
    }

    /**
     * Gets a List of usernames of the users who are being authenticated by this authentication source.
     *
     * @param source The source for which the usernames should be retrieved.
     *
     * @return The List of User objects.
     *
     * @throws SQLException Thrown if there is a problem with the database.
     */

    public List<String> getUsernames(final AuthenticationSource source)
        throws SQLException {
        List<String> usernames = new ArrayList<>();

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_USERNAMES_SQL)) {
            ps.setString(1, source.getSourceId());
            try(ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    usernames.add(rs.getString(1));
                }
            }
        }

        return usernames;
    }

    /**
     * Delete this authentication source from the database.
     *
     * @param source The authentication source to delete
     *
     * @throws SQLException Thrown if there is a problem with the database.
     */

    public void delete(final AuthenticationSource source)
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL)) {
            ps.setString(1, source.getSourceId());
            ps.executeUpdate();
        }
    }


    /**
     * Retrieves all of the AutheticationSource objects as a List.
     *
     * @return The authentication source List.
     *
     * @throws SQLException Thrown if there is a problem accessing the database
     */

    public List<AuthenticationSource> getAll()
        throws SQLException {
        try(Statement stmt = BOMFactory.getCurrentConntection().createStatement()) {
            try(ResultSet rs = stmt.executeQuery(GET_ALL)) {
                List<AuthenticationSource> sources = new ArrayList<>();
                if (rs.next()) {
                    int idx = 1;
                    String currentId = rs.getString(idx++);
                    Map<String, String> currentMap = new HashMap<>();
                    currentMap.put(rs.getString(idx++), rs.getString(idx));
                    do {
                        int rsIdx = 1;
                        String sourceId = rs.getString(rsIdx++);
                        if (!currentId.equals(sourceId)) {
                            sources.add(new AuthenticationSource(currentId,currentMap));

                            currentId = sourceId;
                            currentMap = new HashMap<>();
                        }

                        currentMap.put(rs.getString(rsIdx++), rs.getString(rsIdx));
                    } while (rs.next());
                    sources.add(new AuthenticationSource(currentId, currentMap));
                }

                Collections.sort(sources);

                return sources;
            }
        }
    }

    private static final class InstanceHolder {
        private static final AuthenticationSourceDAO INSTANCE = new AuthenticationSourceDAO();
    }

    public static AuthenticationSourceDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
