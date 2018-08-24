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

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.enterprisepasswordsafe.engine.database.AccessControl;
import com.enterprisepasswordsafe.engine.database.AccessControlDAO;
import com.enterprisepasswordsafe.engine.database.AccessRole;
import com.enterprisepasswordsafe.engine.database.AccessRoleDAO;
import com.enterprisepasswordsafe.engine.database.ApproverListDAO;
import com.enterprisepasswordsafe.engine.database.ConfigurationDAO;
import com.enterprisepasswordsafe.engine.database.ConfigurationOption;
import com.enterprisepasswordsafe.engine.database.HierarchyNode;
import com.enterprisepasswordsafe.engine.database.HierarchyNodeDAO;
import com.enterprisepasswordsafe.engine.database.HistoricalPasswordDAO;
import com.enterprisepasswordsafe.engine.database.IntegrationModuleScriptDAO;
import com.enterprisepasswordsafe.engine.database.Password;
import com.enterprisepasswordsafe.engine.database.PasswordBase;
import com.enterprisepasswordsafe.engine.database.PasswordDAO;
import com.enterprisepasswordsafe.engine.database.RestrictedAccessRequest;
import com.enterprisepasswordsafe.engine.database.RestrictedAccessRequestDAO;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLog;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLogDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.ui.web.utils.DateFormatter;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Obtains the requested password information and sends the user to the ViewPassword page.
 */

public final class ViewPassword extends HttpServlet {

	/**
	 *
	 */
	private static final long serialVersionUID = -2618853020633824143L;

	/**
	 * The attribute used to hold any applicable restriced access request.
	 */

	public static final String RA_REQUEST_ATTRIBUTE = "rar";

	/**
	 * The parameter used to hold the last refresh time and date.
	 */

	public static final String RA_LAST_REFRESH = "ra_last_refresh";

	/**
	 * The request attribute used to hold the human readable date time format.
	 */

	public static final String HUMAN_READABLE_TIMEPOINT = "timepoint_hr";

	/**
	 * The attribute name set when there are integration scripts associated with a password.
	 */

	public static final String SCRIPTS_IN_USE = "scripts";

	/**
	 * The parameter for the reason a password was viewed.
	 */

	public static final String REASON_PARAMETER = "reason";

    /**
     * The page to send the user to if a reason is required and has not been entered
     */

    private static final String REASON_PAGE = "/system/view_password_reason.jsp";

    /**
     * The page to send the user to the password is a restricted access page
     */

    private static final String RESTRICTED_ACCESS_PAGE = "/system/ra_reason.jsp";

    /**
     * The page to send the user to the password is a restricted access page
     */

    private static final String RESTRICTED_ACCESS_EXPIRED_PAGE = "/system/ra_expired.jsp";

    /**
     * The page to send the user to if the restricted access request was denied.
     */

    private static final String RESTRICTED_ACCESS_DENIED_PAGE = "/system/ra_denied.jsp";

    /**
     * The page to send the user to the password is a restricted access page
     */

    private static final String RESTRICTED_ACCESS_HOLDING_PAGE = "/system/ra_holding_page.jsp";

    /**
     * Get the details for the password and display it.
     *
     * @see HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
        // Check to see if this user already has a valid session.
    	try {
			String backAllowed = ConfigurationDAO.getValue(ConfigurationOption.ALLOW_BACK_BUTTON_TO_ACCESS_PASSWORD);
			if( backAllowed == null || backAllowed.equals("false") ) {
		    	HttpSession session = request.getSession(false);
		        String sessionOtid = (String) session.getAttribute("otid");
		        String requestOtid = request.getParameter("otid");
		        if( requestOtid == null ) {
		        	requestOtid = (String) request.getAttribute("otid");
		        }
		        if (sessionOtid == null
		        ||	requestOtid == null
		        ||  !sessionOtid.equals(requestOtid)) {
					throw new ServletException("You can not view passwords using your browsers back button.");
		        }
			}

	        User thisUser = SecurityUtils.getRemoteUser(request);

            if(thisUser.isNonViewingUser()) {
                throw new ServletException("You are not allowed to view passwords.");
            }

	        final ServletUtils servletUtils = ServletUtils.getInstance();
	        String id = servletUtils.getParameterValue(request, SharedParameterNames.PASSWORD_ID_PARAMETER);

	        AccessControl ac;
	        if (thisUser.isAdministrator() || thisUser.isSubadministrator()) {
	            ac = AccessControlDAO.getInstance().getAccessControlEvenIfDisabled(thisUser, id);
	        } else {
	            ac = AccessControlDAO.getInstance().getAccessControl(thisUser, id);
	        }

	        if (ac == null) {
	        	throw new ServletException("You are not allowed to view the selected password.");
	        }

	        String dt = request.getParameter(BaseServlet.DATE_TIME_PARAMETER);
	        PasswordBase thisPassword;
	        if (dt == null || dt.length() == 0) {
	            thisPassword = PasswordDAO.getInstance().getByIdEvenIfDisabled(ac, id);
	        } else {
	        	long timestamp = Long.parseLong(dt);
	            thisPassword = HistoricalPasswordDAO.getInstance().getByIdForTime(ac, id, timestamp);
	            if( thisPassword == null ) {
	                throw new ServletException("The password history is not available for the selected entry");
	            }
	            request.setAttribute(BaseServlet.DATE_TIME_PARAMETER, dt);
	            request.setAttribute(
	            		HUMAN_READABLE_TIMEPOINT,
	            		DateFormatter.convertToDateTimeString(timestamp)
	            	);
	        }


	        thisPassword.decrypt(ac);

	        if(thisPassword instanceof Password
	        && ((Password)thisPassword).getPasswordType() == Password.TYPE_PERSONAL ) {
	        	HierarchyNodeDAO hDAO = HierarchyNodeDAO.getInstance();
	        	String containerNodeId = hDAO.getByName(thisPassword.getId()).getNodeId();
	        	HierarchyNode containerNode = hDAO.getById(containerNodeId);
	        	HierarchyNode personalNode = hDAO.getPersonalNodeForUser(thisUser);
	        	if(personalNode == null || !personalNode.getNodeId().equals(containerNode.getParentId())) {
			        throw new ServletException("You are not allowed to view the selected password.");
	        	}
	        }

	        boolean sendEmail;
	        if(thisPassword instanceof Password) {
	        	sendEmail = ((((Password)thisPassword).getAuditLevel() & Password.AUDITING_EMAIL_ONLY)!=0);
	        } else {
	            Password currentPassword = PasswordDAO.getInstance().getByIdEvenIfDisabled(ac, id);
	        	sendEmail = ((currentPassword.getAuditLevel() & Password.AUDITING_EMAIL_ONLY)!=0);
	        }


	        RestrictedAccessRequest raRequest = null;
	    	String reason = null;
	    	if( thisPassword instanceof Password ) {
	    		Password password = (Password) thisPassword;
	    		if(password.isRaEnabled()) {
	       			String raPage = getRaPage(password, thisUser, request);
	       			if( raPage != null ) {
	    	            request.getRequestDispatcher(raPage).forward(request, response);
	    	            return;
	       			}
	       			raRequest =
	       				(RestrictedAccessRequest) request.getSession().getAttribute(RA_REQUEST_ATTRIBUTE);
	       			reason = raRequest.getReason();
	       			servletUtils.generateMessage(request,
	       					"This is a restricted access password. Your request to view it has been approved by the approproate users.");
	       			request.getSession().removeAttribute(RA_REQUEST_ATTRIBUTE);
	        	}
	    	}

	    	String reasonRequired =
					ConfigurationDAO.getInstance().get(ConfigurationOption.PASSWORD_REASON_FOR_VIEWING_REQUIRED);
	    	boolean logRequired = true;
	    	if( reasonRequired.charAt(0) == 'y') {
		    	reason = request.getParameter(REASON_PARAMETER);
		    	if( reason == null || reason.trim().length() == 0 ) {
		    		String lastReasonViewId =
		    			(String) request.getSession().getAttribute("reason.lastid");
		    		String lastPassword =
		    			(String) request.getSession().getAttribute("reason.password");
		    		if( lastReasonViewId != null
		    		&&	lastReasonViewId.equals(id)
		    		&&	lastPassword != null
		    		&&	lastPassword.equals(thisPassword.getPassword())) {
		    			reason =
		    				(String) request.getSession().getAttribute("reason.text");
		    			logRequired = false;
		    		}
		    	}
	    		request.getSession().removeAttribute("reason.lastid");
	    		request.getSession().removeAttribute("reason.password");
	    		request.getSession().removeAttribute("reason.text");
	    		if( reason == null || reason.trim().length() == 0 ) {
		    		String displayValue = request.getParameter("display");
		    		if( displayValue == null ) {
		    			displayValue = "";
		    		}
		    		request.setAttribute("display", displayValue);
		   			request.setAttribute("id", id);
		   			servletUtils.generateErrorMessage(request, "You must enter a reason for viewing the password.");
		            request.getRequestDispatcher(REASON_PAGE).forward(request, response);
		            return;
		    	}

	    		request.getSession().setAttribute("reason.lastid", id);
		    	request.getSession().setAttribute("reason.password", thisPassword.getPassword());
		   		request.getSession().setAttribute("reason.text", reason);
		   		request.setAttribute("reason", reason);
	       	} else {
	    		request.getSession().removeAttribute("reason.lastid");
	    		request.getSession().removeAttribute("reason.password");
	    		request.getSession().removeAttribute("reason.text");
	       		request.setAttribute("reason", "");
	       	}

	    	if(thisPassword instanceof Password) {
	    		logRequired =
	    			(((Password)thisPassword).getAuditLevel() != Password.AUDITING_NONE);
	    	}

	    	if(logRequired) {
		    	StringBuilder logMessage = new StringBuilder();
		    	logMessage.append("The password was viewed by the user");
		        if (dt != null) {
		            logMessage.append(" as it was at ");
		            logMessage.append(DateFormatter.convertToDateTimeString(Long.parseLong(dt)));
		        }
		        logMessage.append('.');
		        if( reason != null && reason.length() > 0 ) {
		        	logMessage.append(" The reason given was\n\"");
		        	logMessage.append(reason);
		        	logMessage.append('\"');
		            logMessage.append('.');
		        }
		        if( raRequest != null ) {
		        	logMessage.append(" The user(s) who approved the request are; ");

		        	String listId = raRequest.getApproversListId();
		        	for(String approverId : ApproverListDAO.getInstance().getApproverIDs(listId)) {
		        		logMessage.append( " {user:");
		        		logMessage.append( approverId );
		        		logMessage.append( "}," );
		        	}
		        	logMessage.deleteCharAt(logMessage.length()-1);
		        	logMessage.append('.');
		        }
		        TamperproofEventLogDAO.getInstance().create(
							TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
		        			thisUser,
		        			thisPassword,
		        			logMessage.toString(),
		        			sendEmail
		    			);
	    	}

	        String passwordTimeout = ConfigurationDAO.getValue(ConfigurationOption.PASSWORD_ON_SCREEN_TIME);
	        int timeout = Integer.parseInt(passwordTimeout) * DateFormatter.MILLIS_IN_MINUTE;
	        passwordTimeout = Integer.toString(timeout);

	        request.setAttribute(BaseServlet.USER_ATTRIBUTE, thisUser);
	        request.setAttribute("password", thisPassword);
	        request.setAttribute(SharedParameterNames.PASSWORD_TIMEOUT_ATTRIBUTE, passwordTimeout);

	        if( IntegrationModuleScriptDAO.getInstance().hasScripts(thisPassword) ) {
	        	request.setAttribute(SCRIPTS_IN_USE, Boolean.TRUE);
	        } else {
	        	request.setAttribute(SCRIPTS_IN_USE, Boolean.FALSE);
	        }

	        String displayType = ConfigurationDAO.getValue(ConfigurationOption.PASSWORD_DISPLAY_TYPE);
	        request.setAttribute("password_displayType", displayType);

	        String display = request.getParameter("display");
	        if( display == null || display.length() == 0 ) {
	        	String displayDefault = ConfigurationDAO.getValue(ConfigurationOption.PASSWORD_DISPLAY);
	        	display = Boolean.toString(displayDefault.charAt(0) =='s');
	        }
	        request.setAttribute("display", display);

	        request.setAttribute("cfields", thisPassword.getAllCustomFields());

			Boolean showHistory = Boolean.FALSE;
	    	if	( AccessRoleDAO.getInstance().hasRole(
									thisUser.getUserId(),
									thisPassword.getId(),
									AccessRole.HISTORYVIEWER_ROLE) ) {
	    		showHistory = Boolean.TRUE;
	    	} else if			( thisUser.isAdministrator() ) {
				showHistory = Boolean.TRUE;
			} else if	( thisUser.isSubadministrator() ) {
				String showSubadminHistory =
						ConfigurationDAO.getValue(ConfigurationOption.SUBADMINS_HAVE_HISTORY_ACCESS);
				if( showSubadminHistory.charAt(0) == 'Y' ) {
					showHistory = Boolean.TRUE;
				}
			}
			request.setAttribute("showHistoryOption", showHistory);

			if(thisPassword != null && thisPassword.getPassword() != null) {
				request.setAttribute("encodedPassword", thisPassword.getPassword().replace("\"", "\\\""));
			}

			request.getRequestDispatcher("/system/view_password.jsp").forward(request, response);
	    } catch(SQLException ex) {
            Logger.getAnonymousLogger().log(Level.WARNING, "Problem obtaining password details.", ex);
            throw new ServletException("There was a problem obtaining the password details.",ex);
        } catch(GeneralSecurityException ex) {
            Logger.getAnonymousLogger().log(Level.WARNING, "Problem obtaining password details.", ex);
            throw new ServletException("There was a problem obtaining the password details.",ex);
	    }

    }

    /**
     * ViewPassword may have data POSTed to it
     */

    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
    	throws IOException, ServletException {
    	doGet(request, response);
    }

    /**
     * Get the page to divert the user to to handle a restricted access request.
     *
     * @param password The password which is being viewed.
     * @param requester The user attempting to view the password.
     * @param request The request being serviced.
     *
     * @return The page the user should be redirected to, or null if the password
     * should be shown.
     */

    private String getRaPage(final Password password, final User requester,	final HttpServletRequest request)
    	throws SQLException {
    	HttpSession session = request.getSession();

   		RestrictedAccessRequest raRequest =
   			(RestrictedAccessRequest) session.getAttribute(RA_REQUEST_ATTRIBUTE);

   		if( raRequest != null  ) {
   			if( !raRequest.getItemId().equals(password.getId())
   			||	!raRequest.getRequesterId().equals(requester.getUserId())) {
   				session.removeAttribute(RA_REQUEST_ATTRIBUTE);
   				raRequest = null;
   			}
   		}

   		if( raRequest == null ) {
   			raRequest = RestrictedAccessRequestDAO.getInstance().getValidRequest(
   								password.getId(),
   								requester.getUserId()
							);
			session.setAttribute(RA_REQUEST_ATTRIBUTE, raRequest);
   		}

   		if( raRequest == null ) {
   			request.setAttribute("id", password.getId());
   			return RESTRICTED_ACCESS_PAGE;
   		}

		if	(raRequest.hasExpired()) {
			session.removeAttribute(RA_REQUEST_ATTRIBUTE);
   			return RESTRICTED_ACCESS_EXPIRED_PAGE;
   		}

		int blockers = ApproverListDAO.getInstance().countBlockers(raRequest.getApproversListId());
		int blockersNeeded = password.getRaBlockers();
		if   ( blockersNeeded != 0 && blockers >= blockersNeeded){
			session.removeAttribute(RA_REQUEST_ATTRIBUTE);
   			return RESTRICTED_ACCESS_DENIED_PAGE;
   		}

		int approvers = ApproverListDAO.getInstance().countApprovers(raRequest.getApproversListId());
		if (approvers < password.getRaApprovers()){
   			request.setAttribute(
   					RA_LAST_REFRESH,
   					DateFormatter.convertToDateTimeString(DateFormatter.getNow())
				);

   			request.setAttribute("rarId", raRequest.getRequestId());
   			request.setAttribute("ra_refresh_url", "/system/ViewPassword?id="+request.getParameter("id"));
   			return RESTRICTED_ACCESS_HOLDING_PAGE;
   		}

		if( raRequest.getViewedDT() < 0 ) {
			RestrictedAccessRequestDAO.getInstance().setViewedDT(raRequest, DateFormatter.getNow());
		}

   		return null;
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Gets the details about a specific password.";
    }
}
