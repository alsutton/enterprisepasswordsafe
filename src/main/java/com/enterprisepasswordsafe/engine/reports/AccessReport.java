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

import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.database.*;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class AccessReport {

    private static final String GET_ACCESSIBLE_PASSWORDS_FOR_USER_SQL =
            "SELECT item_id FROM user_access_control WHERE user_id = ?";

    private static final String GET_ACCESSIBLE_PASSWORDS_FOR_USER_VIA_GAC_SQL =
            "SELECT gac.group_id, gac.item_id FROM membership m, group_access_control gac "
            + " WHERE m.user_id = ? AND m.group_id = gac.group_id AND gac.rkey is not null ";

    private AccessReport() {
        super();
    }

    public void generateReport(final User user, final PrintWriter printWriter, final String separator)
            throws SQLException, GeneralSecurityException, IOException {
// TODO Look for more efficient algorithm

        GroupDAO gDAO = GroupDAO.getInstance();
        Group adminGroup = gDAO.getAdminGroup(user);
        try(PreparedStatement uacPS = BOMFactory.getCurrentConntection().prepareStatement(GET_ACCESSIBLE_PASSWORDS_FOR_USER_SQL)) {
            try(PreparedStatement gacPS = BOMFactory.getCurrentConntection().prepareStatement(GET_ACCESSIBLE_PASSWORDS_FOR_USER_VIA_GAC_SQL)) {
                Context context = new Context(uacPS, gacPS, printWriter, separator);
                for(User thisUser : UserDAO.getInstance().getAll()) {
                    thisUser.decryptAdminAccessKey(adminGroup);

                    getDirectlyAccessiblePasswords(context, thisUser);
                    getPasswordsAccessibleViaGroup(context, thisUser);
                }
            }
        }
    }


    private void getDirectlyAccessiblePasswords(Context context, User user)
            throws SQLException, IOException, GeneralSecurityException {
        context.directlyAccessiblePS.setString(1, user.getId());
        PasswordDAO passwordDAO = PasswordDAO.getInstance();
        try(ResultSet rsPasswords = context.directlyAccessiblePS.executeQuery()) {
            while (rsPasswords.next()) {
                String passwordId = rsPasswords.getString(1);
                Password thisPassword = passwordDAO.getById(user, passwordId);
                if( thisPassword == null )
                    continue;
                context.output.println(constructDetails( user, thisPassword, null, context.separator));
            }
        }
    }

    private void getPasswordsAccessibleViaGroup(Context context, User user)
            throws SQLException, GeneralSecurityException, IOException {
        context.groupAccessiblePS.setString(1, user.getId());
        try(ResultSet resultSet = context.groupAccessiblePS.executeQuery()) {
            while (resultSet.next()) {
                processGroup(context, user, resultSet);
            }
        }
    }

    private void processGroup(Context context, User user, ResultSet resultSet)
            throws SQLException, GeneralSecurityException, IOException {
        Group group = getGroupIfValid(resultSet);
        if( group == null )
            return;

        String passwordId = resultSet.getString(2);

        AccessControl ac = GroupAccessControlDAO.getInstance().getGac(user, group, passwordId);
        if( ac == null )
            return;

        Password password = PasswordDAO.getInstance().getById(passwordId, ac);
        if( password == null )
            return;

        context.output.println(constructDetails(user, password, group, context.separator));
    }

    private Group getGroupIfValid(ResultSet resultSet)
            throws SQLException {
        String groupId = resultSet.getString(1);
        if( groupId.equals(Group.ADMIN_GROUP_ID) ||  groupId.equals(Group.SUBADMIN_GROUP_ID) ) {
            return  null;
        }

        return GroupDAO.getInstance().getById(groupId);
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

    private static class Context {
        PreparedStatement directlyAccessiblePS;
        PreparedStatement groupAccessiblePS;
        PrintWriter output;
        String separator;

        Context(PreparedStatement directlyAccessiblePS, PreparedStatement groupAccessiblePS,
                PrintWriter output, String separator) {
            this.directlyAccessiblePS = directlyAccessiblePS;
            this.groupAccessiblePS = groupAccessiblePS;
            this.output = output;
            this.separator = separator;
        }
    }


    //------ Singleton

    private static final class InstanceHolder {
        final static AccessReport INSTANCE = new AccessReport();
    }

    public static AccessReport getInstance() {
        return InstanceHolder.INSTANCE;
    }

}
