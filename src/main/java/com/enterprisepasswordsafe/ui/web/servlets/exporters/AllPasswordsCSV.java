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

import com.enterprisepasswordsafe.database.*;
import com.enterprisepasswordsafe.database.actions.PasswordAction;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.sql.SQLException;

public final class AllPasswordsCSV extends BaseExporter {

 	@Override
    protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
    	throws ServletException {
        response.setContentType("text/csv");
        response.setHeader("Content-Disposition", "attachment; filename=\"AllPasswords.csv\"");

        try {
	        User user = SecurityUtils.getRemoteUser(request);
	        TamperproofEventLogDAO.getInstance().create(
					TamperproofEventLog.LOG_LEVEL_REPORTS,
	        		user,
	        		null,
	                "Exported all the passwords using the CSV Report",
	                true
	    		);

	        PrintWriter pw = response.getWriter();
	        String separator = getSeparator();
	        pw.print("Username");
	        pw.print(separator);
	        pw.print("Password");
	        pw.print(separator);
	        pw.print("Location");
	        pw.print(separator);
	        pw.print("Notes");
	        pw.print(separator);
	        pw.println("Status");
	        PasswordDumper dumper = new PasswordDumper(pw);
	        new PasswordProcessor().processAllPasswords(user, dumper);
        } catch(Exception e) {
        	throw new ServletException("The passwords could not be exported due to an error.", e);
        }
    }

    @Override
	public String getServletInfo() {
        return "Exports all of the passwords in a system.";
    }

    private final class PasswordDumper implements PasswordAction {

        private final PrintWriter outputStream;

        private final String separator;

        private PasswordDumper(final PrintWriter newOutputStream) throws SQLException {
            outputStream = newOutputStream;
            separator = getSeparator();
        }

        @Override
		public void process(final HierarchyNode node, final Password password) throws Exception {
            if (password == null || password.getPasswordType() == Password.TYPE_PERSONAL) {
                return;
            }

            outputStream.print(password.getUsername());
            outputStream.print(separator);
            outputStream.print(password.getPassword());
            outputStream.print(separator);
            outputStream.print(password.getLocation());
            outputStream.print(separator);

            String notes = password.getNotes();
            int notesSize = notes.length();
            StringBuffer store = new StringBuffer(notesSize);
            for (int i = 0; i < notesSize; i++) {
                char thisChar = notes.charAt(i);
                if (Character.isWhitespace(thisChar)) {
                    store.append(' ');
                } else if (thisChar == ',') {
                    store.append(' ');
                } else {
                    store.append(thisChar);
                }

            }

            outputStream.print(store.toString());
            outputStream.print(separator);
            if (password.isEnabled()) {
                outputStream.print("Enabled");
            } else {
                outputStream.print("Disabled");
            }
            outputStream.println();
        }
    }
}
