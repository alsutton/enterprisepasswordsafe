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
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.ConfigurationDAO;
import com.enterprisepasswordsafe.engine.database.ConfigurationOption;
import com.enterprisepasswordsafe.engine.database.Group;
import com.enterprisepasswordsafe.engine.database.GroupDAO;
import com.enterprisepasswordsafe.engine.database.HierarchyNode;
import com.enterprisepasswordsafe.engine.database.HierarchyNodeDAO;
import com.enterprisepasswordsafe.engine.database.Password;
import com.enterprisepasswordsafe.engine.database.PasswordDAO;
import com.enterprisepasswordsafe.engine.database.PasswordRestriction;
import com.enterprisepasswordsafe.engine.database.PasswordRestrictionDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.ui.web.utils.DateFormatter;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Servlet to create a new password.
 */

public final class CreateNewPassword extends HttpServlet {

    /**
     * @see HttpServlet#doPost(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
    @Override
    protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException, ServletException {
    	request.setAttribute("error_page", "/system/CreatePassword");
    	try {
	    	Map<String,String> customFields = new TreeMap<String,String>();
			int cfCount = -1;
			int fieldCount = 1;
			while( true ) {
				cfCount++;
				String checkFieldName = "cfok_"+cfCount;
				String checkValue = request.getParameter(checkFieldName);
				if( checkValue == null || checkValue.length() == 0 ) {
					break;
				}

				String deleteCheckFieldName = "cfd_"+cfCount;
				String deleteValue = request.getParameter(deleteCheckFieldName);
				if( deleteValue != null && deleteValue.length() > 0 ) {
					continue;
				}

				customFields.put(
						request.getParameter("cfn_"+cfCount),
						request.getParameter("cfv_"+cfCount)
					);
				fieldCount++;
			}

	    	String newCf = request.getParameter("newCF");
	    	if( newCf != null && newCf.length() > 0 ) {
	    		customFields.put("New Field "+fieldCount, "");
	    		request.setAttribute("cfields", customFields);
	    		request.getRequestDispatcher("/system/CreatePassword").forward(request, response);
	    		return;
	    	}

	        String password1 = request.getParameter("password_1");
	        String password2 = request.getParameter("password_2");
	        if (!password1.equals(password2)) {
	            throw new ServletException("The password has NOT been created because the passwords you typed did not match.");
	        }

	        String username = request.getParameter("username");
	        if( username == null || username.length() == 0 ) {
	        	throw new ServletException("The password has NOT been created because you did not specify a username.");
	        }

	        String location = request.getParameter("location_text");

	        String notes = request.getParameter("notes");
	        if (notes == null) {
	            notes = "";
	        }

	        int audit = Password.AUDITING_FULL;

	        ConfigurationDAO cDAO = ConfigurationDAO.getInstance();
	        String auditing = cDAO.get( ConfigurationOption.PASSWORD_AUDIT_LEVEL );
	        if( auditing == null || auditing.equals(Password.SYSTEM_AUDIT_CREATOR_CHOOSE)) {
	            String auditFlag = request.getParameter("audit");
	            if (auditFlag.charAt(0) == 'L') {
	                audit = Password.AUDITING_LOG_ONLY;
	            } else if (auditFlag.charAt(0) == 'N') {
	                audit = Password.AUDITING_NONE;
	            }
	        } else if ( auditing.equals(Password.SYSTEM_AUDIT_FULL)) {
	            audit = Password.AUDITING_FULL;
	        } else if ( auditing.equals(Password.SYSTEM_AUDIT_LOG_ONLY)) {
	            audit = Password.AUDITING_LOG_ONLY;
	        } else {
	            audit = Password.AUDITING_NONE;
	        }


	        boolean history;
	        String passwordHistory = cDAO.get( ConfigurationOption.STORE_PASSWORD_HISTORY );
			if		  ( passwordHistory.equals(Password.SYSTEM_PASSWORD_RECORD)) {
				history = true;
			} else if ( passwordHistory.equals(Password.SYSTEM_PASSWORD_DONT_RECORD)) {
				history = false;
			} else {
		        String booleanFlag = request.getParameter("history");
		        history = (booleanFlag != null && booleanFlag.equals("y"));
			}

            long expiryDate = getExpiry(request);

	        String restrictionId = request.getParameter("restriction.id");
	        PasswordRestriction control = PasswordRestrictionDAO.getInstance().getById(restrictionId);
	        if (control != null && !control.verify(password1)) {
	            throw new ServletException(
	            		"The password has NOT been created because the password does not meet the minimum requirements ("
	            		+ control.toString() +
	            		").");
	        }

	        int raApprovers = 0,
	        	raBlockers = 0;
	        boolean raEnabled = false;
	        String raEnabledString = request.getParameter("ra_enabled");
	        if( raEnabledString != null && raEnabledString.equals("true") ) {
	        	raEnabled = true;
	        	raApprovers = Integer.parseInt(request.getParameter("ra_approvers"));
	        	raBlockers = Integer.parseInt(request.getParameter("ra_blockers"));
	        }

	        String parentNodeId = ServletUtils.getInstance().getNodeId(request);

	        int type = Password.TYPE_SYSTEM;
	        HierarchyNode parentNode = HierarchyNodeDAO.getInstance().getById(parentNodeId);
	        if( parentNode.getType() == HierarchyNode.USER_CONTAINER_NODE) {
	        	type = Password.TYPE_PERSONAL;
	        }

	        User thisUser = SecurityUtils.getRemoteUser(request);
	        Group adminGroup = GroupDAO.getInstance().getAdminGroup(thisUser);
	        Password newPassword = PasswordDAO.getInstance().create(
	        		thisUser,
	        		adminGroup,
	        		username,
	                password1,
	                location,
	                notes,
	                audit,
	                history,
	                expiryDate,
	                parentNodeId,
	                restrictionId,
	                raEnabled,
	                raApprovers,
	                raBlockers,
	                type,
	                customFields
	            );

	        ServletUtils.getInstance().generateMessage(request, "The password was successfully created.");
	        if( type == Password.TYPE_PERSONAL ) {
	        	response.sendRedirect(request.getContextPath()+"/system/ViewPersonalFolder");
	        } else {
	        	response.sendRedirect(request.getContextPath()+"/subadmin/AlterAccess?id="+newPassword.getId());
	        }
        } catch (ParseException e) {
            redispatchException(e);
    	} catch(SQLException e) {
    		redispatchException(e);
    	} catch(GeneralSecurityException e) {
    		redispatchException(e);
    	}
    }

    /**
     * Get the expiry date from the servlet request.
     *
     * @param request The request being processed.
     *
     * @return The expiry date
     */
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
        String rejectHistoricalExpiry = ConfigurationDAO.getValue(ConfigurationOption.REJECT_HISTORICAL_EXPIRY_DATES);
        if (rejectHistoricalExpiry != null && rejectHistoricalExpiry.equals("Y") && date < DateFormatter.getToday()) {
            throw new ServletException( "The expiry date must be in the future.");
        }

        String maxExpiryDistance = ConfigurationDAO.getValue(ConfigurationOption.MAX_FUTURE_EXPIRY_DISTANCE);
        if( !maxExpiryDistance.equals("0") ) {
            long maxDistance = Long.parseLong(maxExpiryDistance);
            long distance = DateFormatter.daysInPast(date);
            if( distance > maxDistance ) {
                throw new ServletException("The expiry date must be "+maxDistance+" days or less in the future.");
            }
        }

        return date;
    }

    /**
     * Dispatch an exception adding on a message for the base exception
     */

    public void redispatchException(final Exception ex)
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

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Creates a new password";
    }
}
