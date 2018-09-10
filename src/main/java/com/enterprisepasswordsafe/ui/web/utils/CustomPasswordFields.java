package com.enterprisepasswordsafe.ui.web.utils;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.TreeMap;

public class CustomPasswordFields {

    public Map<String, String> extractCustomFieldsFromRequest(HttpServletRequest request) {
        Map<String,String> customFields = new TreeMap<>();
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
        return customFields;
    }
}
