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
import com.enterprisepasswordsafe.engine.passwords.AuditingLevel;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

public final class CreateNewPassword extends AbstractPasswordManipulatingServlet {

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
    	request.setAttribute("error_page", "/system/CreatePassword");
    	try {
	    	Map<String,String> customFields = extractCustomFieldsFromRequest(request);
            if (addCustomFieldIfRequested(request, customFields)) {
	    		request.setAttribute("cfields", customFields);
	    		request.getRequestDispatcher("/system/CreatePassword").forward(request, response);
	    		return;
	    	}

            UsernameAndPassword usernameAndPassword = ensureParametersAreValid(request);
	        String location = request.getParameter("location_text");

	        String notes = request.getParameter("notes");
	        if (notes == null) {
	            notes = "";
	        }

	        AuditingLevel audit = getAuditingLevel(request);
	        boolean history = getHistorySetting(request);
            long expiryDate = getExpiry(request);

	        int raApprovers = 0, raBlockers = 0;
	        boolean raEnabled = false;
	        String raEnabledString = request.getParameter("ra_enabled");
	        if( raEnabledString != null && raEnabledString.equals("true") ) {
	        	raEnabled = true;
	        	raApprovers = Integer.parseInt(request.getParameter("ra_approvers"));
	        	raBlockers = Integer.parseInt(request.getParameter("ra_blockers"));
	        }

	        String parentNodeId = ServletUtils.getInstance().getNodeId(request);
            HierarchyNode parentNode = HierarchyNodeDAO.getInstance().getById(parentNodeId);
            int type = parentNode.getType() == HierarchyNode.USER_CONTAINER_NODE ? Password.TYPE_PERSONAL : Password.TYPE_SYSTEM;

	        User thisUser = SecurityUtils.getRemoteUser(request);
	        Group adminGroup = GroupDAO.getInstance().getAdminGroup(thisUser);
	        Password newPassword = PasswordDAO.getInstance().create(thisUser, adminGroup,
                usernameAndPassword.username, usernameAndPassword.password, location, notes,
                audit, history, expiryDate, parentNodeId, request.getParameter("restriction.id"),
                raEnabled, raApprovers, raBlockers, type, customFields);

	        ServletUtils.getInstance().generateMessage(request, "The password was successfully created.");
	        String redirect = type ==
                    Password.TYPE_PERSONAL ? "/system/ViewPersonalFolder" : "/subadmin/AlterAccess?id="+newPassword.getId();
            response.sendRedirect(request.getContextPath() + redirect);
        } catch (ParseException | SQLException | GeneralSecurityException e) {
    		redispatchException(e);
    	}
    }

    private UsernameAndPassword ensureParametersAreValid(HttpServletRequest request)
            throws ServletException, SQLException {
        String password1 = request.getParameter("password_1");
        String password2 = request.getParameter("password_2");
        if (!password1.equals(password2)) {
            throw new ServletException("The password has NOT been created because the passwords you typed did not match.");
        }

        String username = request.getParameter("username");
        if( username == null || username.length() == 0 ) {
            throw new ServletException("The password has NOT been created because you did not specify a username.");
        }

        String restrictionId = request.getParameter("restriction.id");
        PasswordRestriction control = PasswordRestrictionDAO.getInstance().getById(restrictionId);
        if (control != null && !control.verify(password1)) {
            throw new ServletException(
                    "The password has NOT been created because the password does not meet the minimum requirements ("
                            + control.toString() + ").");
        }


        return new UsernameAndPassword(username, password1);
    }

    private AuditingLevel getAuditingLevel(HttpServletRequest request)
            throws SQLException {
        String auditing = ConfigurationDAO.getInstance().get( ConfigurationOption.PASSWORD_AUDIT_LEVEL );
        AuditingLevel auditingLevel = AuditingLevel.fromRepresentation(auditing);
        if( auditing == null || auditingLevel == AuditingLevel.CREATOR_CHOOSE) {
            return getUserProvidedAuditLevel(request);
        }
        return auditingLevel;
    }

    private AuditingLevel getUserProvidedAuditLevel(HttpServletRequest request) {
        AuditingLevel auditingLevel = AuditingLevel.fromRepresentation(request.getParameter("audit"));
        return auditingLevel == null ? AuditingLevel.FULL : auditingLevel;
    }

    private long getExpiry(final HttpServletRequest request )
            throws ParseException, ServletException, SQLException {
        final String expiry = request.getParameter("expiryDate");
        if (expiry == null || expiry.isEmpty()) {
            return Long.MAX_VALUE;
        }

        DateFormat dateFormatter = DateFormat.getDateInstance();
        Date parsedDate = dateFormatter.parse(expiry);
        Calendar cal = Calendar.getInstance();
        cal.setTime(parsedDate);

        long date = cal.getTimeInMillis();
        ensureExpiryIsValid(date);
        return date;
    }

    private void ensureExpiryIsValid(long date)
            throws ServletException, SQLException {
        String rejectHistoricalExpiry = ConfigurationDAO.getValue(ConfigurationOption.REJECT_HISTORICAL_EXPIRY_DATES);
        if (rejectHistoricalExpiry != null && rejectHistoricalExpiry.equals("Y") && date < DateFormatter.getToday()) {
            throw new ServletException( "The expiry date must be in the future.");
        }

        String maxExpiryDistance = ConfigurationDAO.getValue(ConfigurationOption.MAX_FUTURE_EXPIRY_DISTANCE);
        if( maxExpiryDistance.equals("0") ) {
            return;
        }

        long maxDistance = Long.parseLong(maxExpiryDistance);
        long distance = DateFormatter.daysInPast(date);
        if( distance > maxDistance ) {
            throw new ServletException("The expiry date must be "+maxDistance+" days or less in the future.");
        }
    }

    private void redispatchException(final Exception ex)
    	throws ServletException {
		final StringBuilder message = new StringBuilder("The password could not be created due to an error");
		final String exceptionMessage = ex.getMessage();
		if(exceptionMessage != null && !exceptionMessage.isEmpty()) {
			message.append(" (");
			message.append(exceptionMessage);
			message.append(')');
		}
		message.append('.');
		throw new ServletException(message.toString(), ex);
    }

    @Override
	public String getServletInfo() {
        return "Creates a new password";
    }

    private static class UsernameAndPassword {
        String username;
        String password;

        UsernameAndPassword(final String username, final String password) {
            this.username = username;
            this.password = password;
        }
    }
}
