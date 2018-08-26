package com.enterprisepasswordsafe.engine.database;

import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Base class which can be used for fetching otehr object types from the database.
 *
 * @param <T> The type of object being fetched
 */
abstract class StoredObjectManipulator<T> {

    private String getByIdSql;

    private String getByNameSql;

    private String getCountSql;

    StoredObjectManipulator(final String getByIdSql, final String getByNameSql, final String getCountSql) {
        this.getByIdSql = getByIdSql;
        this.getByNameSql = getByNameSql;
        this.getCountSql = getCountSql;
    }

    abstract T newInstance(ResultSet rs, int startIndex) throws SQLException;

    public T getById(final String id)
            throws SQLException {
        return fetchObjectIfExists(getByIdSql, id);
    }

    public T getByName(final String name)
            throws SQLException {
        return fetchObjectIfExists(getByNameSql, name);
    }

    T fetchObjectIfExists(String sql, final String... parameters)
            throws SQLException {
        if (sql == null) {
            throw new RuntimeException("Unsupported operation");
        }
        try(PreparedStatement ps =  BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            setParameters(ps, parameters);
            ps.setMaxRows(1);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? newInstance(rs, 1) : null;
            }
        }
    }

    boolean exists(String sql, final String... parameters)
        throws SQLException{
        try(PreparedStatement ps =  BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            setParameters(ps, parameters);
            ps.setMaxRows(1);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    List<T> getMultiple(final String sql, final String... parameters)
            throws SQLException {
        List<T> results = new ArrayList<>();
        try (PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            setParameters(ps, parameters);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    try {
                        results.add(newInstance(rs, 1));
                    } catch(Exception e) {
                        Logger.getAnonymousLogger().log(Level.SEVERE, "Error fetching object.", e);
                    }
                }
            }
        }
        return results;
    }

    public int countActiveUsers( )
            throws SQLException {
        try (Statement statement = BOMFactory.getCurrentConntection().createStatement()) {
            try(ResultSet rs = statement.executeQuery(getCountSql)) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        }
    }

    private void setParameters(PreparedStatement ps, String... parameters)
            throws SQLException {
        int parameterId = 1;
        for (String parameter: parameters) {
            ps.setString(parameterId, parameter);
            parameterId++;
        }
    }

    void runResultlessParameterisedSQL(String sql, String... parameters)
            throws SQLException {
        try (PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            setParameters(ps, parameters);
            ps.execute();
        }
    }
}
