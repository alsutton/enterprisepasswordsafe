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
import com.enterprisepasswordsafe.engine.passwords.AuditingLevel;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;
import com.enterprisepasswordsafe.ui.web.utils.EmailerThread;
import com.enterprisepasswordsafe.ui.web.utils.RedirectException;
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
import java.util.Set;

public final class ChangePassword extends AbstractPasswordManipulatingServlet {

	private final UserClassifier userClassifier = new UserClassifier();

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
        String csrfToken = request.getParameter("token");
        if(csrfToken == null
                || !csrfToken.equals(request.getSession(true).getAttribute("csrfToken"))) {
            throw new ServletException("Permission Denied");
        }

        String passwordId = request.getParameter("id");
        try {
            Map<String,String> customFields = extractCustomFieldsFromRequest(request);
            addNewCustomFieldIfRequested(request, customFields);

            PasswordDAO pDAO = PasswordDAO.getInstance();

			request.setAttribute("error_page", "/system/EditPassword?id=" + passwordId);

			User thisUser = SecurityUtils.getRemoteUser(request);
            Context passwordContext = getPasswordContext(thisUser, passwordId);
            passwordContext.password.setCustomFields(customFields);
			updatePassword(request, thisUser, passwordContext.password);
            storeUpdate(thisUser, pDAO, passwordContext);
			sendChangeNotifications(pDAO, passwordContext.password);

			ServletUtils.getInstance().generateMessage(request, "The password was successfully changed.");
		} catch (RedirectException e) {
			request.getRequestDispatcher(e.getDestination()).forward(request, response);
			return;
    	} catch (Exception ex) {
    		throw new ServletException("The password could not be updated due to an error.", ex);
    	}

        String newOtid = request.getAttribute("nextOtid").toString();
        response.sendRedirect(request.getContextPath()+"/system/ViewPassword?id="+passwordId+"&otid="+newOtid);
    }

    private void sendChangeNotifications(PasswordDAO pDAO, Password password)
			throws SQLException {
		String smtpEnabled = ConfigurationDAO.getValue(ConfigurationOption.SMTP_ENABLED);
		if (smtpEnabled != null && smtpEnabled.equals("Y")) {
			try {
				Set<String> emailAddresses = pDAO.getEmailsOfUsersWithAccess(password);
				String message =  "The password for "+password+" has changed.";
				EmailerThread emailer = new EmailerThread(emailAddresses, "Change of password", message);
				emailer.start();
			} catch (Exception excpt) {
				log("Error attempting to send password change notifications.",
						excpt);
			}
		}
	}

	private void addNewCustomFieldIfRequested(HttpServletRequest request, Map<String, String> customFields)
            throws RedirectException {
        String newCf = request.getParameter("newCF");
        if( newCf != null && newCf.length() > 0 ) {
            customFields.put("New Field "+customFields.size(), "");
            request.setAttribute("cfields", customFields);
            throw new RedirectException("/system/EditPassword");
        }
    }

    private Context getPasswordContext(User user, String passwordId)
            throws GeneralSecurityException, ServletException, SQLException, IOException {
        if (passwordId == null && passwordId.length() == 0) {
            return new Context(new Password(), null);
        }

        AccessControl ac = AccessControlDAO.getInstance().getAccessControlEvenIfDisabled(user, passwordId);
        if (ac == null || ac.getModifyKey() == null) {
            throw new ServletException("You can not update the passsword.");
        }
        return new Context(UnfilteredPasswordDAO.getInstance().getById(passwordId, ac), ac);
    }

    private void storeUpdate(User user, PasswordDAO pDAO, Context passwordContext)
            throws GeneralSecurityException, SQLException, IOException {
        if (passwordContext.accessControl != null) {
            pDAO.update(passwordContext.password, user, passwordContext.accessControl);
            return;
        }

        pDAO.storeNewPassword(passwordContext.password, user);
        if (passwordContext.password.getAuditLevel().shouldTriggerLogging()) {
            TamperproofEventLogDAO.getInstance().create(TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
                    user, passwordContext.password, "Created the password.",
					passwordContext.password.getAuditLevel().shouldTriggerEmail());
        }
    }


    /**
     * Checks to see if a date is in the past.
     *
     * @param date
     *            The date to check (in the format yyyymmdd)
     *
     * @return true if the date is in the past, false if not.
     */

    private boolean isInPast(final long date) {
        long today = DateFormatter.getToday();
        return date < today;
    }

    @Override
	public String getServletInfo() {
        return "Updates a password";
    }

    private void updatePassword(final HttpServletRequest request, final User thisUser,
    		final Password thePassword )
			throws SQLException, ParseException, ServletException, RedirectException {
        String password = extractPassword(request);
    	String restrictionId = extractRestrictionID(request);
        if(!isRestrictionCompliant(password, restrictionId)) {
        	ServletUtils.getInstance().generateErrorMessage(request, "The password does not comply with the restrictions specified");
        	throw new RedirectException("/system/EditPassword");
        }

        if( password != null ) {
        	thePassword.setPassword(password);
        }
        thePassword.setNotes( request.getParameter("notes") );
        thePassword.setUsername( extractUsername(request) );
        thePassword.setLocation( extractLocation(request) );
        setAuditing( request, thePassword);
        setHistoryRecording( request, thePassword );
        setExpiry( request, thePassword);
		if( userClassifier.isPriviledgedUser(thisUser)) {
			String enabled = request.getParameter("enabled");
			thePassword.setEnabled(enabled != null && enabled.equals("Y"));
			thePassword.setRestrictionId(extractRestrictionID(request));
			setRestrictedAccess(request, thePassword);
		}
	}

	/**
	 * Extract the password from the request.
	 *
	 * @param request The HttpServletRequest request being serviced.
	 *
	 * @return The password to use.
	 */
	private String extractPassword(final HttpServletRequest request)
		throws ServletException {
        String password1 = request.getParameter("password_1");
        String password2 = request.getParameter("password_2");
        if (password1 != null && password1.length() > 0) {
            if (!password1.equals(password2)) {
                throw new ServletException("The password was not updated because the passwords typed did not match.");
            }
            return password1;
        }
        return null;
	}

	/**
	 * Extract the username from the request.
	 *
	 * @param request The HttpServletRequest being serviced.
	 */
	private String extractUsername(final HttpServletRequest request)
		throws ServletException{
        String username = request.getParameter("username");
        if( username == null || username.length() == 0 ) {
            throw new ServletException("The password has NOT been updated because you did not specify a valid username.");
        }
        return username;
	}

	/**
	 * Extract the location from a request.
	 */

	private String extractLocation(final HttpServletRequest request) {
        String location = request.getParameter("location_text");
        return (location == null) ? "<UNKNOWN>" : location;
	}

	/**
	 * Extract the password restriction ID.
	 */

	private String extractRestrictionID( final HttpServletRequest request ) {
		return request.getParameter("restriction_id");
	}

	private boolean isRestrictionCompliant(final String password, final String restrictionId )
		throws SQLException {
        PasswordRestriction control = PasswordRestrictionDAO.getInstance().getById(restrictionId);
        return control == null || control.verify(password);
	}

	/**
	 * Set the auditing level from a HttpServletRequest.
	 *
	 * @param request The request being processed.
	 * @param password The password to set the value in.
	 */
	private void setAuditing(final HttpServletRequest request, final Password password ) {
		AuditingLevel auditingLevel = AuditingLevel.fromRepresentation(request.getParameter("audit"));
       	password.setAuditLevel(auditingLevel == null ? AuditingLevel.FULL : auditingLevel);
	}

	/**
	 * Set the history recording level from a HttpServletRequest.
	 *
	 * @param request The request being processed.
	 * @param password The password to set the value in.
	 */
	private void setHistoryRecording(final HttpServletRequest request, final Password password )
		throws SQLException {
        boolean newHistoryStored;
        String passwordHistory = ConfigurationDAO.getValue( ConfigurationOption.STORE_PASSWORD_HISTORY );
        switch (passwordHistory) {
            case Password.SYSTEM_PASSWORD_RECORD:
                newHistoryStored = true;
                break;
            case Password.SYSTEM_PASSWORD_DONT_RECORD:
                newHistoryStored = false;
                break;
            default:
                String booleanFlag = request.getParameter("history");
                newHistoryStored = (booleanFlag != null && booleanFlag.equals("y"));
                break;
        }
        if (password.isHistoryStored() && !newHistoryStored) {
        	HistoricalPasswordDAO.getInstance().writeNullEntry(password);
        }
        password.setHistoryStored(newHistoryStored);
	}

	/**
	 * Set the expiry date from a HttpServletRequest.
	 *
	 * @param request The request being processed.
	 * @param password The password to set the value in.
	 */
	private void setExpiry(final HttpServletRequest request, final Password password )
            throws ParseException, ServletException, SQLException {
        final String expiry = request.getParameter("expiryDate");
        if (expiry == null || expiry.isEmpty()) {
            password.setExpiry(Long.MAX_VALUE);
            return;
        }

        DateFormat dateFormatter = DateFormat.getDateInstance();
        Date parsedDate = dateFormatter.parse(expiry);
        Calendar cal = Calendar.getInstance();
        cal.setTime(parsedDate);
        long date = cal.getTimeInMillis();
        String rejectHistoricalExpiry = ConfigurationDAO.getValue(ConfigurationOption.REJECT_HISTORICAL_EXPIRY_DATES);
        if (rejectHistoricalExpiry != null && rejectHistoricalExpiry.equals("Y") && isInPast(date)) {
            throw new ServletException( "The expiry date must be in the future.");
        }

        ensureExpiryIsValid(date);
        password.setExpiry(date);
	}


	private void ensureExpiryIsValid(long date)
			throws SQLException, ServletException {
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

	/**
	 * Set the restricted access settings from a HttpServletRequest.
	 *
	 * @param request The request being processed.
	 * @param password The password to set the value in.
	 */
	private void setRestrictedAccess(final HttpServletRequest request, final Password password ) {
        String raEnabled = request.getParameter("ra_enabled");
        if( raEnabled != null && raEnabled.equals("Y") ) {
            password.setRaEnabled(true);
            String approvers = request.getParameter("ra_approvers");
            if( approvers != null ) {
                password.setRaApprovers(Integer.parseInt(approvers));
            }
            String blockers = request.getParameter("ra_blockers");
            if( blockers != null ) {
                password.setRaBlockers(Integer.parseInt(blockers));
            }
        } else {
            password.setRaEnabled(false);
        }
	}

	private static class Context {
	    private final Password password;
	    private final AccessControl accessControl;

        Context(Password password, AccessControl accessControl) {
	        this.password = password;
	        this.accessControl = accessControl;
        }

    }
}
