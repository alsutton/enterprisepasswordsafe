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

import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;


public abstract class ImporterServlet extends HttpServlet {
    @Override
	protected final void doPost(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
    	request.setAttribute("error_page", "/system/import_results.jsp");
        setImportAttributes(request);

        User importingUser = SecurityUtils.getRemoteUser(request);
        String parentNode = ServletUtils.getInstance().getNodeId(request);

        FileItemFactory factory = new DiskFileItemFactory();
        ServletFileUpload upload = new ServletFileUpload(factory);

        ImportStatus importStatus = new ImportStatus();
        try {
            for (FileItem fi : upload.parseRequest(request)) {
                if (!fi.isFormField()) {
                    importFile(request, importingUser, parentNode, importStatus, fi);
                }
            }
        } catch (FileUploadException | IOException ex) {
            importStatus.addError( ex.getMessage() );
        }

        request.setAttribute(BaseServlet.COUNT, importStatus.getImportCount());
        request.setAttribute(BaseServlet.ERROR_TEXT_LIST, importStatus.getErrors());
        request.setAttribute("errorCount", Integer.toString(importStatus.getErrorCount()));

        request.getRequestDispatcher("/system/import_results.jsp").forward(request, response);
    }

    private void importFile(HttpServletRequest request, User importingUser, String parentNode,
                             ImportStatus importStatus, FileItem fileItem)
        throws IOException {
        String data = new String(fileItem.get());

        try (StringReader reader = new StringReader(data)) {
            try (CSVParser parser = new CSVParser(reader, CSVFormat.RFC4180.withEscape('\\'))) {
                for (CSVRecord record : parser) {
                    try {
                        importEntry(request, importingUser, parentNode, record);
                        importStatus.increaseImportCount();
                    } catch (Exception ex) {
                        String errorText = getErrorMessage(importStatus, ex);
                        super.log(errorText, ex);
                        importStatus.addError(errorText);
                    }
                }
            }
        }
    }

    private String getErrorMessage(final ImportStatus status, final Exception ex) {
        return "Error on entry #" + status.importCount + ": "+ex.getMessage();
    }

    public abstract void importEntry(HttpServletRequest request, User importingUser, String parentNode,
                                    CSVRecord csvRecord)
		throws ServletException;

    protected abstract void setImportAttributes(final HttpServletRequest request)
    	throws ServletException;

    private static class ImportStatus {
        private int importCount = 0;
        private List<String> errors = new ArrayList<>();

        void increaseImportCount() {
            importCount++;
        }

        int getImportCount() {
            return importCount;
        }

        void addError(final String error) {
            errors.add(error);
        }

        int getErrorCount() {
            return errors.size();
        }

        List<String> getErrors() {
            return errors;
        }
    }
}
