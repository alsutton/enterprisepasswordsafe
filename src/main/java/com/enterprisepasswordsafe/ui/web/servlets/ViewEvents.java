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
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.enterprisepasswordsafe.engine.database.ConfigurationDAO;
import com.enterprisepasswordsafe.engine.database.ConfigurationOption;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLogDAO;
import com.enterprisepasswordsafe.engine.database.TamperproofEventLogDAO.EventsForDay;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;

public final class ViewEvents extends HttpServlet {

    private static final String WEB_UI_PAGE = "/admin/view_events.jsp";
    private static final String CSV_EXPORT_PAGE = "/admin/export_events_csv.jsp";

    private static final String DATE_FORMAT = "dd-MMM-yyyy";

    private static final String START_DATE_PARAMETER = "startdate";
    private static final String END_DATE_PARAMETER = "enddate";
    private static final String USER_LIMIT_PARAMETER = "ulimit";

    @Override
    public void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        request.setAttribute("isNotQuery", Boolean.TRUE);
        request.getRequestDispatcher(WEB_UI_PAGE).forward(request, response);
    }

    @Override
	protected void doPost(final HttpServletRequest request, final HttpServletResponse response)
    	throws ServletException, IOException {
    	SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);

        Calendar startDate = getStartDate(request, sdf);
        Calendar endDate = getEndDate(request, sdf);

        String userLimit =
                getParameterWhichHasMinusOneAsDefault(request, USER_LIMIT_PARAMETER);
        String passwordLimit =
                getParameterWhichHasMinusOneAsDefault(request, SharedParameterNames.PASSWORD_ID_PARAMETER);
        User remoteUser =
                getCurrentUserAndStoreInRequest(request);

        try {
            List<EventsForDay> events = TamperproofEventLogDAO.getInstance().
                    getEventsForDateRange(
                            startDate.getTimeInMillis(),
                            endDate.getTimeInMillis(),
                            userLimit,
                            passwordLimit,
                            remoteUser,
                            false,
                            true
                    );
            request.setAttribute("events", events);
        } catch (SQLException | GeneralSecurityException e) {
            throw new ServletException(e);
        }

        String nextPage = determineNextPage(request);
        request.getRequestDispatcher(nextPage).forward(request, response);
    }

    private User getCurrentUserAndStoreInRequest(HttpServletRequest request)
            throws ServletException {
        User currentUser = SecurityUtils.getRemoteUser(request);
        request.setAttribute("viewing.user", currentUser);
        return currentUser;
    }

    private Calendar getStartDate(final HttpServletRequest request, final SimpleDateFormat sdf) {
        Calendar startDate = convertFromDatePicker(sdf, request.getParameter(START_DATE_PARAMETER));
        startDate.set(Calendar.HOUR_OF_DAY, 0);
        startDate.set(Calendar.MINUTE, 0);
        startDate.set(Calendar.SECOND, 0);
        startDate.set(Calendar.MILLISECOND, 0);

        request.setAttribute(START_DATE_PARAMETER, sdf.format(startDate.getTime()));

        return startDate;
    }

    private Calendar getEndDate(final HttpServletRequest request, final SimpleDateFormat sdf) {
        Calendar endDate = convertFromDatePicker(sdf,request.getParameter(END_DATE_PARAMETER));
        endDate.set(Calendar.HOUR_OF_DAY, 23);
        endDate.set(Calendar.MINUTE, 59);
        endDate.set(Calendar.SECOND, 59);
        endDate.set(Calendar.MILLISECOND, 999);

        request.setAttribute(END_DATE_PARAMETER, sdf.format(endDate.getTime()));

        return endDate;
    }

    private String getParameterWhichHasMinusOneAsDefault(HttpServletRequest request, String parameter) {
        String value = ServletUtils.getInstance().getParameterValue(request, parameter);

        if (value != null && value.equals("-1")) {
            value = null;
        }

        if(value != null) {
            request.setAttribute(parameter, value);
        }

        return value;
    }

    private Calendar convertFromDatePicker(final SimpleDateFormat sdf, final String string) {
        Calendar cal = Calendar.getInstance();

        // An empty string is taken as the current time.
        if(string == null || string.isEmpty()) {
            return cal;
        }

    	try {
    		Date date = sdf.parse(string);
    		cal.setTime(date);
    	} catch(Exception ex) {
    		// Exceptions mean the time couldn't be set, so we just return now.
    	}
        return cal;
    }

    private String determineNextPage(HttpServletRequest request)
        throws ServletException {
        if( isCSVExport(request) ) {
            prepareExport(request);
            return CSV_EXPORT_PAGE;
        }

        return WEB_UI_PAGE;
    }

    private boolean isCSVExport(final HttpServletRequest request) {
        String isExport = request.getParameter("export");
        return (isExport != null && !isExport.isEmpty() && isExport.charAt(0) == 'Y');
    }

    private void prepareExport(HttpServletRequest request)
        throws ServletException {
        try {
            request.setAttribute("delimiter", ConfigurationDAO.getInstance().get(ConfigurationOption.REPORT_SEPARATOR));
        } catch (SQLException e) {
            throw new ServletException(e);
        }
    }
}
