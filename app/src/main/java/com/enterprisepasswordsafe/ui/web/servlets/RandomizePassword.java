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

package com.enterprisepasswordsafe.ui.web.servlets;

import com.enterprisepasswordsafe.database.BOMFactory;
import com.enterprisepasswordsafe.database.IntegrationModule;
import com.enterprisepasswordsafe.model.dao.IntegrationModuleConfigurationDAO;
import com.enterprisepasswordsafe.model.dao.IntegrationModuleDAO;
import com.enterprisepasswordsafe.model.dao.IntegrationModuleScriptDAO;
import com.enterprisepasswordsafe.model.dao.PasswordDAO;
import com.enterprisepasswordsafe.engine.utils.PasswordRestrictionUtils;
import com.enterprisepasswordsafe.model.persisted.LogEntry;
import com.enterprisepasswordsafe.model.dao.LoggingDAO;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.integration.PasswordChanger;
import com.enterprisepasswordsafe.ui.web.servlets.utils.AccessControlFetcher;
import com.enterprisepasswordsafe.ui.web.utils.PasswordGenerator;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletPaths;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

public final class RandomizePassword extends HttpServlet {

    private final AccessControlFetcher accessControlFetcher = new AccessControlFetcher();

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        try {
            User user = SecurityUtils.getRemoteUser(request);
            String passwordId = request.getParameter("id");
            AccessControl ac = accessControlFetcher.getModifyAccessControl(user, passwordId);

            PasswordDAO pDAO = PasswordDAO.getInstance();
            Password password = pDAO.getById(passwordId, ac);
            String newPassword = createNewPassword(password);
            runIntegrationScripts(password, newPassword);
            password.setPassword(newPassword);
            pDAO.update(password, user, ac);

            LoggingDAO.getInstance().create(LogEntry.LOG_LEVEL_OBJECT_MANIPULATION,
                    user, password, "Randomized the password.",
                    password.getAuditLevel().shouldTriggerEmail());
            ServletUtils.getInstance().generateMessage(request, "The password has been changed.");
        } catch (Exception ex) {
            throw new ServletException("There was a problem talking to the system holding the password.", ex);
        }

        request.getRequestDispatcher(ServletPaths.getExplorerPath()).forward(request, response);
    }

    private String createNewPassword(Password password) throws SQLException {
        PasswordRestrictionDAO prDAO = PasswordRestrictionDAO.getInstance();
        PasswordRestrictionUtils control = prDAO.getById(password.getRestrictionId());
        if (control == null) {
            control = prDAO.getById(PasswordRestrictionUtils.MIGRATED_RESTRICTION_ID);
        }
        return PasswordGenerator.getInstance().generate(control, true);
    }

    private void runIntegrationScripts(Password password, String newPassword)
            throws UnsupportedEncodingException, SQLException, ClassNotFoundException,
            NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        Map<String, String> passwordProperties = createChangeProperties(password, newPassword);

        final IntegrationModuleDAO imDAO = IntegrationModuleDAO.getInstance();
        final IntegrationModuleConfigurationDAO imcDAO = IntegrationModuleConfigurationDAO.getInstance();
        final Connection dbConnection = BOMFactory.getCurrentConntection();
        for (IntegrationModuleScript thisScript :
                IntegrationModuleScriptDAO.getInstance().getScriptsForPassword(password.getId())) {
            final Map<String, String> scriptProperties = imcDAO.getProperties(thisScript, password);
            final IntegrationModule module = imDAO.getById(thisScript.getModuleId());
            final PasswordChanger changer = imDAO.getPasswordChangerInstance(module);
            changer.changePassword(dbConnection, scriptProperties, passwordProperties, thisScript.getScript());
        }
    }

    private Map<String, String> createChangeProperties(Password password, String newPassword) {
        final Map<String, String> passwordProperties = new HashMap<>();
        passwordProperties.put(PasswordChanger.USERNAME_PROPERTY, password.getUsername());
        passwordProperties.put(PasswordChanger.SYSTEM, password.getLocation());
        passwordProperties.put(PasswordChanger.OLD_PASSWORD, password.getPassword());

        passwordProperties.put(PasswordChanger.NEW_PASSWORD, newPassword);
        return passwordProperties;
    }

    @Override
    public String getServletInfo() {
        return "Servlet to alter the scripts associated with a password";
    }
}
