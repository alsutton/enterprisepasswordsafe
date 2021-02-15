package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.database.actions.PasswordAction;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.model.dao.AccessControlDAO;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class PasswordProcessor {

    /**
     * The SQL to get all the active passwords to be acted on.
     */

    private static final String GET_ALL_PASSWORDS_FOR_ACTION_BY_USER_SQL =
            "SELECT " + PasswordDAO.PASSWORD_FIELDS + " FROM passwords pass, user_access_control uac "
        + " WHERE uac.user_id = ? AND uac.item_id = pass.password_id AND (pass.enabled is null OR pass.enabled = 'Y')";

    /**
     * The SQL to get all the active passwords to be acted on.
     */

    private static final String GET_ALL_PASSWORDS_FOR_ACTION_BY_GROUP_SQL =
            "SELECT " + PasswordDAO.PASSWORD_FIELDS + "  FROM passwords pass, group_access_control gac, membership mem "
         + " WHERE mem.user_id  = ? AND mem.group_id    = gac.group_id AND gac.item_id = pass.password_id "
         + " AND (pass.enabled is null OR pass.enabled = 'Y')";


    /**
     * The SQL to get all the active passwords to be acted on.
     */

    private static final String GET_ALL_PASSWORDS_FOR_ACTION_BY_USER_EVEN_IF_DISABLED_SQL =
            "SELECT " + PasswordDAO.PASSWORD_FIELDS + "  FROM passwords pass, user_access_control uac "
        + " WHERE uac.user_id = ?AND uac.item_id = pass.password_id";

    /**
     * The SQL to get all the active passwords to be acted on.
     */

    private static final String GET_ALL_PASSWORDS_FOR_ACTION_BY_GROUP_EVEN_IF_DISABLED_SQL =
            "SELECT " + PasswordDAO.PASSWORD_FIELDS + " FROM passwords pass, group_access_control gac, membership  mem "
                    + " WHERE mem.user_id = ? AND mem.group_id    = gac.group_id AND gac.item_id = pass.password_id ";


    private final UserClassifier userClassifier = new UserClassifier();

    /**
     * Performs an action on all passwords stored in the database.
     *
     * @param user The user performing the action.
     * @param action The object which will act on each password.
     *
     * @throws Exception Any exception can be thrown during the processing of passwords.
     */

    public void processAllPasswords(final User user, final PasswordAction action) throws Exception {
        List<String> processedIds = new ArrayList<>();
        if (userClassifier.isAdministrator(user)) {
            processAllPasswordsWork(user, action, GET_ALL_PASSWORDS_FOR_ACTION_BY_USER_EVEN_IF_DISABLED_SQL, processedIds);
            processAllPasswordsWork(user, action, GET_ALL_PASSWORDS_FOR_ACTION_BY_GROUP_EVEN_IF_DISABLED_SQL, processedIds);
        } else {
            processAllPasswordsWork(user, action, GET_ALL_PASSWORDS_FOR_ACTION_BY_USER_SQL, processedIds);
            processAllPasswordsWork(user, action, GET_ALL_PASSWORDS_FOR_ACTION_BY_GROUP_SQL, processedIds);
        }
    }

    /**
     * Performs an action on all passwords stored in the database.
     *
     * @param user The user performing the action.
     * @param action The object which will act on each password.
     * @param sql The SQL to use to get the passwords.
     * @param processedIds The List of IDs which have been processed
     *
     * @throws Exception Any exception can be thrown during the processing of passwords.
     */

    public void processAllPasswordsWork(final User user,
                                        final PasswordAction action, final String sql,
                                        final List<String> processedIds)
            throws Exception {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            ps.setString(1, user.getId());
            try (ResultSet rs = ps.executeQuery()){
                AccessControlDAO acDAO = AccessControlDAO.getInstance();
                while (rs.next()) {
                    final String id = rs.getString(1);
                    if (processedIds.contains(id)) {
                        continue;
                    }
                    final AccessControl ac = acDAO.getAccessControl(user, id);
                    if( ac == null ) {
                        continue;
                    }
                    final Password thisPassword = new Password(id, rs.getBytes(2), ac);
                    action.process(null, thisPassword);
                    processedIds.add(id);
                }
            }
        }
    }
}
