package com.enterprisepasswordsafe.database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class JDBCBase {

    void runResultlessParameterisedSQL(String sql, String... parameters)
            throws SQLException {
        try (PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            setParameters(ps, parameters);
            ps.execute();
        }
    }

    void setParameters(PreparedStatement ps, String... parameters)
            throws SQLException {
        int parameterId = 1;
        for (String parameter: parameters) {
            ps.setString(parameterId, parameter);
            parameterId++;
        }
    }

    boolean exists(String sql, String... parameters)
            throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            setParameters(ps, parameters);
            ps.setMaxRows(1);

            try(ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }
}
