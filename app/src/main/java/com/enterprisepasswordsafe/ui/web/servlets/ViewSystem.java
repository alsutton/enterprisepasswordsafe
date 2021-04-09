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
import com.enterprisepasswordsafe.model.dao.UserDAO;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.sql.DatabaseMetaData;
import java.util.Map;
import java.util.TreeMap;


/**
 * Servlet to take the user to the view system details screen.
 */

public final class ViewSystem extends HttpServlet {

    /**
     * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
     */
	@Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
    	throws ServletException {
        Map<String,String> systemProperties = new TreeMap<>();

        try {
	        DatabaseMetaData metaData = BOMFactory.getCurrentConntection().getMetaData();

	        try {
	            systemProperties.put(
	                    "Enabled Users",
	                    Integer.toString(UserDAO.getInstance().countActiveUsers())
	                );
	        } catch (Exception ex) {
	            log("Error counting enabled users.", ex);
	        }

	        systemProperties.put("EPS Version", "20120418-DEV"); //CheckLicence.CURRENT_VERSION_NUMBER+"."+CheckLicence.CURRENT_PATCH_NUMBER);
	        systemProperties.put("Database", metaData.getDatabaseProductName());
	        systemProperties.put("Database URL", metaData.getURL());
	        systemProperties.put("OS", System.getProperty("os.name"));
	        systemProperties.put("System Type", System.getProperty("os.arch"));
	        systemProperties
	                .put("JVM Vendor", System.getProperty("java.vm.vendor"));
	        systemProperties.put("JVM Name", System.getProperty("java.vm.name"));
	        systemProperties.put("JVM Version", System
	                .getProperty("java.vm.version"));
	        systemProperties.put("JVM Classes", convertSemisToLineBreaks(System
	                .getProperty("java.class.path")));

	        request.setAttribute("sysinfo", systemProperties);

	        request.getRequestDispatcher("/admin/showsystem.jsp").forward(request, response);
        } catch(Exception ex) {
        	throw new ServletException("There was a problem obtaining the the information to show.", ex);
        }
    }

    /**
     * Converts any semicolons in the string into line breaks.
     *
     * @param original
     *            The original string.
     *
     * @return The converted string.
     */

    private String convertSemisToLineBreaks(final String original) {
        if (original == null) {
            return null;
        }

        int originalLength = original.length();
        if (originalLength == 0) {
            return "";
        }

        StringBuilder convertedString = new StringBuilder(originalLength);
        for (int i = 0; i < originalLength; i++) {
            char thisCharacter = original.charAt(i);
            if (thisCharacter == File.pathSeparatorChar) {
                convertedString.append('\n');
            } else {
                convertedString.append(thisCharacter);
            }
        }

        return convertedString.toString();
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Servlet to show information relating to the system";
    }
}
