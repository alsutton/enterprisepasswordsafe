package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.passwords.AuditingLevel;
import com.enterprisepasswordsafe.engine.utils.PasswordUtils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public abstract class PasswordStoreManipulator
    extends StoredObjectManipulator<Password> {

    /**
     * The fields needed to create a Password object from a ResultSet.
     */

    static final String PASSWORD_FIELDS = PasswordBase.PASSWORD_BASE_FIELDS
            + ", pass.enabled, pass.audited, pass.history_stored, pass.restriction_id, "
            + "pass.ra_enabled, pass.ra_approvers, pass.ra_blockers, pass.ptype";

    /**
     * The SQL to update a password within the database.
     */

    private static final String UPDATE_PASSWORD_SQL = "UPDATE passwords SET enabled = ?, audited = ?, " +
        "history_stored = ?, restriction_id = ?, ra_enabled = ?, ra_approvers = ?, ra_blockers = ?, " +
        "ptype = ?, password_data = ? WHERE password_id = ?";


    /**
     * The SQL to get all the active passwords to be acted on.
     */

    private static final String DELETE_SQL = "DELETE FROM passwords WHERE password_id = ?";

    PasswordStoreManipulator(String getByIdSql) {
        super(getByIdSql, null, null);
    }

    @Override
    Password newInstance(ResultSet rs)
            throws SQLException {
        Password password = new Password(rs.getString(1), rs.getBytes(1 + 1));

        int idx = 1 + 2;
        String value = rs.getString(idx++);
        if (value != null) {
            password.setEnabled(value.equals("Y"));
        }

        value = rs.getString(idx++);
        if (value != null) {
            switch (value) {
                case "Y":
                    password.setAuditLevel(AuditingLevel.FULL);
                    break;
                case "L":
                    password.setAuditLevel(AuditingLevel.LOG_ONLY);
                    break;
                default:
                    password.setAuditLevel(AuditingLevel.NONE);
                    break;
            }
        }

        value = rs.getString(idx++);
        if (value != null) {
            password.setHistoryStored(value.equals("Y"));
        }

        value = rs.getString(idx++);
        if (value != null) {
            password.setRestrictionId(value);
        }

        value = rs.getString(idx++);
        if (value != null) {
            password.setRaEnabled(value.equals("Y"));
        }

        password.setRaApprovers(rs.getInt(idx++));
        password.setRaBlockers(rs.getInt(idx++));
        password.setPasswordType(rs.getInt(idx));

        return password;

    }

    public Password getById(String id, AccessControl ac)
            throws SQLException, IOException, GeneralSecurityException {
        if (id == null) {
            return null;
        }
        Password password = super.getById(id);
        if (password == null) {
            return null;
        }
        password.decryptPasswordProperties(ac);
        return password;
    }

    List<Password> getMultiple(User accessingUser, final String sql, final String... parameters)
            throws SQLException, GeneralSecurityException, IOException {
        List<Password> results = super.getMultiple(sql, parameters);
        if (results.isEmpty()) {
            return results;
        }

        AccessControlDAO accessControlDAO = AccessControlDAO.getInstance();
        List<Password> removeList = new ArrayList<>();
        for (Password result : results) {
            AccessControl accessControl = accessControlDAO.getAccessControl(accessingUser, result);
            if (accessControl == null) {
                removeList.add(result);
            } else {
                result.decryptPasswordProperties(accessControl);
            }
        }
        results.removeAll(removeList);

        return results;
    }


    public void update(final Password password, final User modifyingUser)
            throws SQLException, GeneralSecurityException, IOException {
        AccessControl ac = AccessControlDAO.getInstance().getAccessControl(modifyingUser, password);
        if(ac.getModifyKey() == null) {
            throw new GeneralSecurityException("Unable to get a write access control to modify the password");
        }
        update(password, modifyingUser, ac);
    }

    public void update(final Password password, final User modifyingUser, final AccessControl ac)
            throws SQLException, GeneralSecurityException, IOException {
        update(password, ac);

        // Write the password with the data encrypted
        if (password.isHistoryStored()) {
            HistoricalPasswordDAO.getInstance().writeHistoryEntry(password, ac);
        }

        if( password.getPasswordType() != Password.TYPE_PERSONAL
        &&  password.getAuditLevel() != AuditingLevel.NONE) {
            TamperproofEventLogDAO.getInstance().create(TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
                modifyingUser, password, "Changed the password",
                    password.getAuditLevel().shouldTriggerEmail());
        }
    }

    public void update(final Password password, final AccessControl ac)
            throws SQLException, GeneralSecurityException, IOException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_PASSWORD_SQL)) {
            int idx = 1;
            if (password.isEnabled()) {
                ps.setString(idx++, null);
            } else {
                ps.setString(idx++, "N");
            }
            ps.setString(idx++, password.getAuditLevel().toString());
            ps.setString(idx++, password.isHistoryStored() ? "Y" : "N");
            ps.setString(idx++, password.getRestrictionId());
            ps.setString(idx++, password.isRaEnabled() ? "Y" : "N");
            ps.setInt(idx++, password.getRaApprovers());
            ps.setInt(idx++, password.getRaBlockers());
            ps.setInt(idx++, password.getPasswordType());
            ps.setBytes(idx++, PasswordUtils.encrypt(password, ac));

            ps.setString(idx, password.getId());
            ps.executeUpdate();
        }
    }

    public void delete(final User deletingUser, final Password password)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if(password == null) {
            return;
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL)) {
            ps.setString(1, password.getId());
            ps.executeUpdate();

            if( password.getPasswordType() != Password.TYPE_PERSONAL ) {
                TamperproofEventLogDAO.getInstance().create(TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
                        deletingUser, null, "Deleted the password " + password.toString(),
                        password.getAuditLevel().shouldTriggerEmail());
            }
        }
    }
}
