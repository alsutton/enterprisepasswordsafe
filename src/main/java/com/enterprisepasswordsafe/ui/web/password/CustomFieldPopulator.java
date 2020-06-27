package com.enterprisepasswordsafe.ui.web.password;

import com.enterprisepasswordsafe.database.ConfigurationDAO;

import javax.servlet.http.HttpServletRequest;
import java.sql.SQLException;
import java.util.Map;
import java.util.TreeMap;

public class CustomFieldPopulator {

    private ConfigurationDAO configurationDAO;

    public CustomFieldPopulator() {
        configurationDAO = ConfigurationDAO.getInstance();
    }

    public void populateRequestWithDefaultCustomFields(HttpServletRequest request) throws SQLException {
        Map<String,String> customFields = new TreeMap<>();
        int i = 0;
        String fieldName, fieldValue;
        while( (fieldName = configurationDAO.get("custom_fn"+i, null)) != null ) {
            fieldValue = configurationDAO.get("custom_fv"+i, "");
            customFields.put(fieldName, fieldValue);
            i++;
        }
        request.setAttribute("cfields", customFields);

    }
}
