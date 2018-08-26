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

package com.enterprisepasswordsafe.engine.reports;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Sends the access rule report to a PrintWriter
 */

public class AccessReport
    implements ExternalInterface {

    /**
     * The query to get the passwords a user has direct access to.
     */

    private static final String GET_ACCESSIBLE_PASSWORDS_FOR_USER_SQL =
            "SELECT item_id FROM user_access_control WHERE user_id = ?";

    /**
     * The query to get the passwords a user has access to via GACs.
     */

    private static final String GET_ACCESSIBLE_PASSWORDS_FOR_USER_VIA_GAC_SQL =
            "SELECT gac.group_id, gac.item_id FROM membership m, group_access_control gac "
            + " WHERE m.user_id = ? AND m.group_id = gac.group_id AND gac.rkey is not null ";

    /**
     * Private constructor to prevent instantiation
     */

    private AccessReport() {
        super();
    }

    /**
     * Generate the user access report.
     *
     * @param user The user requesting the report.
     * @param printWriter The PrintWriter to send the report to.
     * @param separator The separator to use between elements on a line.
     */
    public void generateReport(final User user, final PrintWriter printWriter, final String separator)
            throws SQLException, GeneralSecurityException, IOException {
        GroupDAO gDAO = GroupDAO.getInstance();
        Group adminGroup = gDAO.getAdminGroup(user);

        PreparedStatement uacPS =
                BOMFactory.getCurrentConntection().prepareStatement(GET_ACCESSIBLE_PASSWORDS_FOR_USER_SQL);
        try {
            PreparedStatement gacPS =
                    BOMFactory.getCurrentConntection().prepareStatement(GET_ACCESSIBLE_PASSWORDS_FOR_USER_VIA_GAC_SQL);
            try {
// TODO Look for more efficient algorithm
                PasswordDAO pDAO = PasswordDAO.getInstance();
                GroupAccessControlDAO gacDAO = GroupAccessControlDAO.getInstance();

                for(User thisUser : UserDAO.getInstance().getAll()) {
                    thisUser.decryptAdminAccessKey(adminGroup);

                    uacPS.setString(1, thisUser.getUserId());
                    ResultSet rsPasswords = uacPS.executeQuery();
                    try {
                        while (rsPasswords.next()) {
                            String passwordId = rsPasswords.getString(1);

                            Password thisPassword = pDAO.getById(thisUser, passwordId);
                            if( thisPassword == null )
                                continue;
                            printWriter.println(constructDetails( thisUser, thisPassword, null,	separator));
                        }
                    } finally {
                        DatabaseConnectionUtils.close(rsPasswords);
                    }

                    gacPS.setString(1, thisUser.getUserId());
                    rsPasswords = gacPS.executeQuery();
                    try {
                        while (rsPasswords.next()) {
                            int idx = 1;
                            String groupId = rsPasswords.getString(idx++);
                            if( groupId.equals(Group.ADMIN_GROUP_ID)
                                    ||  groupId.equals(Group.SUBADMIN_GROUP_ID) ) {
                                continue;
                            }

                            Group group = gDAO.getById(groupId);
                            if( group == null )
                                continue;

                            String passwordId = rsPasswords.getString(idx);

                            AccessControl ac = gacDAO.getGac(thisUser, group, passwordId);
                            if( ac == null )
                                continue;

                            Password password = pDAO.getById(passwordId, ac);
                            if( password == null )
                                continue;

                            printWriter.println(constructDetails(thisUser, password, group, separator));
                        }
                    } finally {
                        DatabaseConnectionUtils.close(rsPasswords);
                    }
                }
            } finally {
                DatabaseConnectionUtils.close(gacPS);
            }
        } finally {
            DatabaseConnectionUtils.close(uacPS);
        }

    }

    private String constructDetails(final User user, final Password password,
                                    final Group group,  final String separator) {
        final StringBuilder details = new StringBuilder();
        details.append(user.getUserName());
        details.append(separator);
        details.append(password.getUsername());
        details.append('@');
        details.append(password.getLocation());
        details.append(separator);
        if (group == null) {
            details.append("None");
        } else {
            details.append(group.getGroupName());
        }
        details.append(separator);
        if (password.getReadKey() == null) {
            details.append("NONE");
        } else if (password.getModifyKey() == null ) {
            details.append("Read-Only");
        } else {
            details.append("Read-Write");
        }

        return details.toString();
    }

    //------ Singleton

    private static final class InstanceHolder {
        final static AccessReport INSTANCE = new AccessReport();
    }

    public static AccessReport getInstance() {
        return InstanceHolder.INSTANCE;
    }

}
