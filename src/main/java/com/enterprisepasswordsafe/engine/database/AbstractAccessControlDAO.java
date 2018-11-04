package com.enterprisepasswordsafe.engine.database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class AbstractAccessControlDAO {

    public static final int ACCESS_CONTROL_FIELD_COUNT = 4;

    Permissions getPermissions(PreparedStatement preparedStatement)
            throws SQLException {
        Permissions permissions = new Permissions();
        try(ResultSet rs = preparedStatement.executeQuery()) {
            while( rs.next() ) {
                String role = rs.getString(1);
                if( rs.wasNull() ) {
                    continue;
                }

                if( role.equals(AccessRole.APPROVER_ROLE) ) {
                    permissions.canApproveRARequest = true;
                } else if (role.equals(AccessRole.HISTORYVIEWER_ROLE)) {
                    permissions.canViewHistory = true;
                }
            }
        }
        return permissions;
    }

    static class Permissions {
        boolean canApproveRARequest;
        boolean canViewHistory;

        Permissions() {
            canApproveRARequest = false;
            canViewHistory = false;
        }
    }
}
