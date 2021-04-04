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

package com.enterprisepasswordsafe.passwordprocessor.actions.password;

import com.enterprisepasswordsafe.model.ConfigurationOptions;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.dao.ConfigurationDAO;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.User;
import com.enterprisepasswordsafe.passwordprocessor.actions.PasswordAction;

import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;


/**
 * Class used to filter expiring passwords.
 */

public class ExpiringAccessiblePasswordsAction implements PasswordAction
{
    /**
     * The default number of days before expiry when a warning is produced.
     */

    private static final int DEFAULT_PASSWORD_EXPIRY_WARNING_DAYS = 7;

    /**
     * The current date.
     */

    private final Date now;

    /**
     * The date for expiry warnings.
     */

    private final Date expiryWarning;

    /**
     * The node id for the users password id.
     */

    private final HierarchyNode personalNode;

    /**
     * The expiring accessible passwords
     */

    private final Set<Password> expired = new HashSet<>();

    /**
     * The expired accessible passwords
     */

    private final Set<Password> expiring = new HashSet<>();

    public ExpiringAccessiblePasswordsAction(final User user, final DAORepository daoRepository) {
        super();

        Calendar expiryCal = Calendar.getInstance();
        this.now = expiryCal.getTime();

        ConfigurationDAO configurationDAO = daoRepository.getConfigurationDAO();
        String warningPeriod = configurationDAO.get(ConfigurationOptions.DAYS_BEFORE_EXPIRY_TO_WARN);
        if (warningPeriod != null && warningPeriod.length() > 0) {
            try {
                expiryCal.add(Calendar.DAY_OF_MONTH, Integer.parseInt(warningPeriod));
            } catch (NumberFormatException ex) {
            	configurationDAO.delete(ConfigurationOptions.DAYS_BEFORE_EXPIRY_TO_WARN);
            }
        } else {
            expiryCal.add(Calendar.DAY_OF_MONTH, DEFAULT_PASSWORD_EXPIRY_WARNING_DAYS);
        }
        this.expiryWarning = expiryCal.getTime();

        this.personalNode = daoRepository.getHierarchyNodeDAO().getPersonalNodeForUser(user);
    }

    /**
     * Analyse a specific password and handle its expiry state.
     *
     * @param testPassword The password to check.
     */
    @Override
	public void process(final Password testPassword) {
        Date expiry = testPassword.getExpiry();
        if (expiry == null || isPersonalPassword(testPassword)) {
            return;
        }

        Date expiryDate = testPassword.getExpiry();
        if (expiryDate.before(now)) {
            expired.add(testPassword);
        } else if (expiryDate.before(expiryWarning)) {
            expiring.add(testPassword);
        }
    }

    private boolean isPersonalPassword(Password password) {
        HierarchyNode location = password.getParentNode();
        if(personalNode == null) {
            return false;
        }

        while(location != null && !location.equals(personalNode)) {
            location = location.getParent();
        }
        return location != null;
    }

    public Set<Password> getExpired() {
        return expired;
    }

    public Set<Password> getExpiring() {
        return expiring;
    }
}
