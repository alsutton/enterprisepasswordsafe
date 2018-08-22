package com.enterprisepasswordsafe.engine.database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Base class which can be used for fetching otehr object types from the database.
 *
 * @param <T> The type of object being fetched
 */
abstract class ObjectFetcher<T> {

    private String getByIdPreparedStatement;

    private String getByNamePreparedStatement;

    ObjectFetcher(final String getByIdPreparedStatement, final String getByNamePreparedStatement) {
        this.getByIdPreparedStatement = getByIdPreparedStatement;
        this.getByNamePreparedStatement = getByNamePreparedStatement;
    }

    abstract T newInstance(ResultSet rs, int startIndex) throws SQLException;

    public T getById(final String id)
            throws SQLException {
        try (PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(getByIdPreparedStatement)) {
            return fetchObjectIfExists(ps, id);
        }
    }

    public T getByName(final String name)
            throws SQLException {
        try(PreparedStatement ps =  BOMFactory.getCurrentConntection().prepareStatement(getByNamePreparedStatement)) {
            return fetchObjectIfExists(ps, name);
        }
    }

    private T fetchObjectIfExists(PreparedStatement ps, String parameter)
            throws SQLException {
        ps.setString(1, parameter);
        ps.setMaxRows(1);
        try(ResultSet rs = ps.executeQuery()) {
            return rs.next() ? newInstance(rs, 1) : null;
        }
    }



}
