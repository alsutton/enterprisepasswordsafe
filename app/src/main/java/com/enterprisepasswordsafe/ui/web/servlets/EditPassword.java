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

import com.enterprisepasswordsafe.database.*;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.Map;
import java.util.TreeMap;

public final class EditPassword extends HttpServlet {

    @Override
    public void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	doGet(request, response);
    }

    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        try {
            Password password = getPasswordIfValidRequest(request);
	        ServletUtils servletUtils = ServletUtils.getInstance();

	        request.setAttribute("password_id", password.getId());
	        servletUtils.setAttributeAllowingOverride(request, "username", password.getUsername());

	        addPasswordText(request, password);
	        addRestrictionInformation(request, servletUtils, password);
            addEntryFieldType(request);
            addLocationOptions(request, servletUtils, password);
	    	servletUtils.setAttributeAllowingOverride(request, "enabled", password.isEnabled() ? "Y" : "N");
            addExpiryDetails(request, servletUtils, password);
	    	addRestrictedAccessRequestDetails(request, servletUtils, password);
	        addAuditingState(request, servletUtils, password);
	    	request.setAttribute("password_history", ConfigurationDAO.getValue(ConfigurationOption.STORE_PASSWORD_HISTORY));
	    	servletUtils.setAttributeAllowingOverride( request, "history", Boolean.toString(password.isHistoryStored()));
            addCustomFields(request, password);
	    	servletUtils.setAttributeAllowingOverride( request, "notes", password.getNotes() );

	    	request.getRequestDispatcher("/system/edit_password.jsp").forward(request, response);
        } catch(SQLException | GeneralSecurityException e) {
        	throw new ServletException("There was a problem obtaining the password details.", e);
        }
    }

    private Password getPasswordIfValidRequest(HttpServletRequest request)
            throws SQLException, ServletException, GeneralSecurityException, IOException {
        String id = ServletUtils.getInstance().getParameterValue(request, SharedParameterNames.PASSWORD_ID_PARAMETER);
        User thisUser = SecurityUtils.getRemoteUser(request);
        AccessControl ac = AccessControlDAO.getInstance().getAccessControlEvenIfDisabled(thisUser, id);
        if (ac == null) {
            throw new ServletException("You are not allowed to view the selected password.");
        }
        return UnfilteredPasswordDAO.getInstance().getById(id, ac);
    }

    private void addPasswordText(HttpServletRequest request,Password password) {
        String passwordText = password.getPassword();
        String password1 = request.getParameter("password_1");
        if(password1 == null || password1.isEmpty()) {
            request.setAttribute("password_1", passwordText);
        } else {
            request.setAttribute("password_1", password1);
        }
        String password2 = request.getParameter("password_2");
        if(password2 == null || password2.isEmpty()) {
            request.setAttribute("password_2", passwordText);
        } else {
            request.setAttribute("password_2", password1);
        }
    }

    private void addEntryFieldType(HttpServletRequest request)
            throws SQLException {
        String passwordFieldType = "password";
        String hiddenPassword = ConfigurationDAO.getValue(ConfigurationOption.HIDDEN_PASSWORD_ENTRY);
        if( hiddenPassword.equalsIgnoreCase("false") ) {
            passwordFieldType="text";
        }
        request.setAttribute("passwordFieldType", passwordFieldType);
    }

    private void addLocationOptions(HttpServletRequest request, ServletUtils servletUtils, Password password)
            throws SQLException {
        servletUtils.setAttributeAllowingOverride(request, "location_text", password.getLocation());
        String hideLocations = ConfigurationDAO.getValue(ConfigurationOption.PASSWORD_HIDE_SYSTEM_SELECTOR);
        if( hideLocations.charAt(0) == 'n') {
            request.setAttribute( "locations_set", LocationDAO.getInstance().getAll() );
        }
    }

    private void addRestrictionInformation(HttpServletRequest request, ServletUtils servletUtils, Password password)
            throws SQLException {
        PasswordRestrictionDAO prDAO = PasswordRestrictionDAO.getInstance();
        request.setAttribute( "restriction_list", prDAO.getAll() );
        String restrictionId = password.getRestrictionId();
        if( restrictionId == null ) {
            restrictionId = PasswordRestriction.MIGRATED_RESTRICTION_ID;
        }

        PasswordRestriction currentRestriction = prDAO.getById(restrictionId);
        if( currentRestriction != null && currentRestriction.isRestrictive() ) {
            request.setAttribute("currentRestrictionId", restrictionId);
            request.setAttribute("currentRestrictionName", currentRestriction.getName());
            servletUtils.generateMessage(request,
                    "The password must meet the following restrictions : "+currentRestriction.toString());
        } else {
            request.setAttribute("currentRestrictionId", "");
        }
    }

    private void addExpiryDetails(HttpServletRequest request, ServletUtils servletUtils, Password password)
            throws SQLException {
        long expiryDate;
        PasswordRestriction restriction = PasswordRestrictionDAO.getInstance().getById(password.getRestrictionId());
        long expiry = password.getExpiry();
        if( restriction != null && restriction.getLifetime() > 0 ) {
            expiryDate = DateFormatter.getDateInFuture(restriction.getLifetime());
        } else if (expiry != Long.MAX_VALUE) {
            expiryDate = expiry;
        } else {
            expiryDate = DateFormatter.getToday();
        }

        Calendar cal = Calendar.getInstance();
		cal.setTimeInMillis(expiryDate);
		DateFormat dateFormatter = DateFormat.getDateInstance();
		request.setAttribute("expiry", dateFormatter.format(cal.getTime()));
		if( expiry < Long.MAX_VALUE ) {
			request.setAttribute("password_expiry", password.getExpiryInHumanForm() );
			servletUtils.setAttributeAllowingOverride(request, "noExpiry", "N");
		} else {
			servletUtils.setAttributeAllowingOverride(request, "noExpiry", "Y");
		}
	}

    private void addRestrictedAccessRequestDetails(HttpServletRequest request, ServletUtils servletUtils, Password password) {
		servletUtils.setAttributeAllowingOverride(request, "ra_enabled", password.isRaEnabled() ? "Y" : "N");
		servletUtils.setAttributeAllowingOverride(request, "ra_approvers", Integer.toString(password.getRaApprovers()) );
		servletUtils.setAttributeAllowingOverride(request, "ra_blockers", Integer.toString(password.getRaBlockers())	);
	}

	private void addAuditingState(HttpServletRequest request, ServletUtils servletUtils, Password password)
            throws SQLException {
        request.setAttribute("password_audit", ConfigurationDAO.getValue(ConfigurationOption.PASSWORD_AUDIT_LEVEL));
        servletUtils.setAttributeAllowingOverride( request, "audit", password.getAuditLevel().toString() );
    }

	private void addCustomFields(HttpServletRequest request,Password password) {
        Object cFields = request.getAttribute("cfields");
        if( cFields == null ) {
            Map<String,String> customFields = password.getAllCustomFields();
            if( customFields != null ) {
                cFields = new TreeMap<>(customFields);
            }
        }
        if( cFields != null ) {
            request.setAttribute("cfields", cFields);
        }
    }

    @Override
	public String getServletInfo() {
        return "Obtains the information to be used in the password editing screen.";
    }
}
