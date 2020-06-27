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

package com.enterprisepasswordsafe.ui.web.servlets.exporters;

import com.enterprisepasswordsafe.database.TamperproofEventLog;
import com.enterprisepasswordsafe.database.TamperproofEventLogDAO;
import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.engine.reports.AccessReport;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

/**
 * Servlet to generate the user access report.
 */

public final class UserAccessCSV extends BaseExporter {

    /**
     * @see BaseExporter#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
	@Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
    	throws ServletException {
        response.setContentType("text/csv");
        response.setHeader("Content-Disposition", "attachment; filename=\"UserAccess.csv\"");

        try {
	        User user = SecurityUtils.getRemoteUser(request);
	        TamperproofEventLogDAO.getInstance().create(
					TamperproofEventLog.LOG_LEVEL_REPORTS,
	        		user,
	        		null,
	                "Exported all the access rules using the CSV Report",
	                true
	    		);

	        PrintWriter pw = response.getWriter();

	        String separator = getSeparator();
	        pw.print("User");
	        pw.print(separator);
	        pw.print("Password");
	        pw.print(separator);
	        pw.print("Group");
	        pw.print(separator);
	        pw.print("Access");
	        pw.println();

            AccessReport.getInstance().generateReport(user, pw, separator);

        } catch(Exception e) {
        	throw new ServletException("The access controls could not be exported due to an error.", e);
        }

    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */

    @Override
	public String getServletInfo() {
        return "Exports the user access information";
    }
}
