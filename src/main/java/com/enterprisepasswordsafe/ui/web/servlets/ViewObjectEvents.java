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

import java.security.GeneralSecurityException;
import java.util.Calendar;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLogDAO.EventsForDay;
import com.enterprisepasswordsafe.ui.web.utils.DateFormatter;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

public final class ViewObjectEvents extends HttpServlet {

    @Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
    	throws ServletException {
    	try {
	        User remoteUser = SecurityUtils.getRemoteUser(request);
	        String passwordLimit = ServletUtils.getInstance().getParameterValue(request, SharedParameterNames.PASSWORD_ID_PARAMETER);
	        if (passwordLimit == null) {
	        	throw new RuntimeException("A password was not specified.");
	        }

	        boolean allowedAccess = false;
			if	( AccessRoleDAO.getInstance().hasRole(
								remoteUser.getUserId(),
								passwordLimit,
								AccessRole.HISTORYVIEWER_ROLE) ) {
				allowedAccess = Boolean.TRUE;
			} else if	( remoteUser.isAdministrator() ) {
				allowedAccess = Boolean.TRUE;
			} else if	( remoteUser.isSubadministrator() ) {
				String showSubadminHistory =
						ConfigurationDAO.getValue(ConfigurationOption.SUBADMINS_HAVE_HISTORY_ACCESS);
				if( showSubadminHistory.charAt(0) == 'Y' ) {
					allowedAccess = Boolean.TRUE;
				}
			}
			if(!allowedAccess) {
				throw new GeneralSecurityException("You are not allowed to view the history of that password.");
			}

	        String day = request.getParameter("start_day");
	        String month = request.getParameter("start_month");
	        String year = request.getParameter("start_year");
	        long startDate = DateFormatter.combineDate(day, month, year);
	        if (startDate < 0) {
	            startDate = DateFormatter.getToday();
	        }


	        day = request.getParameter("end_day");
	        month = request.getParameter("end_month");
	        year = request.getParameter("end_year");
	        long endDate = DateFormatter.combineDate(day, month, year);
	        if (endDate < 0) {
	            endDate = DateFormatter.getToday();
	        }

	    	AccessControl ac = AccessControlDAO.getInstance().getAccessControl(remoteUser, passwordLimit);
	    	if( ac == null ) {
	        	throw new GeneralSecurityException("You are not allowed to view the history for that password.");
	    	}
	        Password thePassword = PasswordDAO.getInstance().getById(passwordLimit, ac);
	        if( thePassword == null ) {
	        	throw new GeneralSecurityException("The password was not found.");
	        }

	    	request.setAttribute("object.name", thePassword.toString());


	        List<EventsForDay> events = TamperproofEventLogDAO.getInstance().
	        					getEventsForDateRange( startDate, endDate, null,
	    							passwordLimit, remoteUser, true, false);

	        request.setAttribute(SharedParameterNames.PASSWORD_ID_PARAMETER, passwordLimit);

	        request.setAttribute("events", events);
	        request.setAttribute("viewing.user", remoteUser);

	        Calendar cal = Calendar.getInstance();
	        cal.setTimeInMillis(startDate);
	        request.setAttribute("start_day",	cal.get(Calendar.DAY_OF_MONTH));
	        request.setAttribute("start_month",	cal.get(Calendar.MONTH));
	        request.setAttribute("start_year",	cal.get(Calendar.YEAR));

	        cal.setTimeInMillis(endDate);
	        request.setAttribute("end_day",		cal.get(Calendar.DAY_OF_MONTH));
	        request.setAttribute("end_month",	cal.get(Calendar.MONTH));
	        request.setAttribute("end_year",	cal.get(Calendar.YEAR));
	        request.setAttribute(BaseServlet.USER_LIST, UserSummaryDAO.getInstance().getSummaryList());

	        request.getRequestDispatcher("/system/view_object_events.jsp").forward(request, response);
    	} catch(Exception ex) {
    		throw new ServletException("There was a problem retrieving the data for the date given.", ex);
    	}
    }
}
