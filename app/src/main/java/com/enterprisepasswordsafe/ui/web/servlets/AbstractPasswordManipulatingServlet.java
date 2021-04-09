package com.enterprisepasswordsafe.ui.web.servlets;

import com.enterprisepasswordsafe.model.dao.ConfigurationDAO;
import com.enterprisepasswordsafe.model.ConfigurationOptions;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import java.sql.SQLException;
import java.util.Map;
import java.util.TreeMap;

public abstract class AbstractPasswordManipulatingServlet extends HttpServlet {

    Map<String, String> extractCustomFieldsFromRequest(HttpServletRequest request) {
        Map<String,String> customFields = new TreeMap<>();
        int cfCount = -1;

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

            customFields.put(request.getParameter("cfn_"+cfCount), request.getParameter("cfv_"+cfCount));
        }

        return customFields;
    }

    boolean addCustomFieldIfRequested(HttpServletRequest request, Map<String,String> customFields) {
        String newCf = request.getParameter("newCF");
        if( newCf == null || newCf.length() == 0 ) {
            return false;
        }

        customFields.put("New Field "+customFields.size(), "");
        request.setAttribute("cfields", customFields);
        return true;
    }

    boolean getHistorySetting(HttpServletRequest request)
            throws SQLException {
        String passwordHistory = ConfigurationDAO.getInstance().get( ConfigurationOptions.STORE_PASSWORD_HISTORY );
        if		  ( passwordHistory.equals(Password.SYSTEM_PASSWORD_RECORD)) {
            return true;
        }
        if ( passwordHistory.equals(Password.SYSTEM_PASSWORD_DONT_RECORD)) {
            return false;
        }

        String booleanFlag = request.getParameter("history");
        return (booleanFlag != null && booleanFlag.equals("y"));
    }
}
