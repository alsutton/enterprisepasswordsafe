package com.enterprisepasswordsafe.engine.logging;

import com.enterprisepasswordsafe.database.*;
import com.enterprisepasswordsafe.database.derived.UserSummary;

import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.StringTokenizer;

public class LogEventParser {
    private static final String DATE_FORMAT = "dd MMM yyyy '-' HH:mm:ss";


    private String valueOfToken(final String variable)
            throws SQLException {
        int colonIdx = variable.indexOf(':');
        if (colonIdx == -1) {
            return variable;
        }

        String variableType = variable.substring(0, colonIdx);
        String variableId = variable.substring(colonIdx + 1);

        if (variableType.equals("user")) {
            UserSummary theUser = UserSummaryDAO.getInstance().getById(variableId);
            if (theUser != null) {
                return theUser.getName();
            }

            return "user with the id " + variableId;
        }

        if (variableType.equals("group")) {
            Group theGroup = GroupDAO.getInstance().getById(variableId);
            if( theGroup != null ) {
                return theGroup.getGroupName();
            }

            return "group with the id " + variableId;
        }

        if (variableType.equals("node")) {
            HierarchyNode theNode = HierarchyNodeDAO.getInstance().getById(variableId);
            if (theNode != null) {
                return theNode.getName();
            }

            return "node with the id " + variableId;
        }

        return "<< UNKNOWN >>";
    }

    public String getParsedMessage(final String event)
            throws SQLException {
        if (event == null) {
            return null;
        }

        StringBuilder parsedValue = new StringBuilder();
        StringTokenizer tokenizer = new StringTokenizer(event, "{");
        while (tokenizer.hasMoreTokens()) {
            String thisToken = tokenizer.nextToken();

            // Check to see the data is closed.
            int closeBracketIdx = thisToken.indexOf('}');
            if (closeBracketIdx == -1) {
                parsedValue.append(thisToken);
                continue;
            }

            // Get the variable name and the
            parsedValue.append(valueOfToken(thisToken.substring(0,closeBracketIdx)));
            parsedValue.append(thisToken.substring(closeBracketIdx + 1));
        }

        return parsedValue.toString();
    }


    /**
     * Returns a textual discription of this event
     *
     * @param eventLogEntry The event log entry to be expanded.
     * @param item The item the entry refers to.
     *
     * @return A textual description of the event.
     *
     * @throws SQLException Thrown if there is a storing retrieving the information.
     */

    public String getFullMessage(TamperproofEventLog eventLogEntry, final AccessControledObject item)
            throws SQLException {
        StringBuilder details = new StringBuilder(1024);

        // Format the date
        details.append("Date : ");
        long datetime = eventLogEntry.getDateTime();
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(datetime);
        SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
        details.append(sdf.format(cal.getTime()));
        details.append("\n");

        // Add the user informtion
        String userId = eventLogEntry.getUserId();
        User theUser = UserDAO.getInstance().getById(userId);
        details.append("User : ");
        if (theUser != null) {
            details.append(theUser.getUserName());
        } else {
            details.append("with the ID ");
            details.append(userId);
        }

        if( item != null ) {
            details.append("\n");
            details.append("Object involved: ");
            details.append(item.toString());
        }

        details.append("\n\n");

        // Add the event
        details.append(getParsedMessage(eventLogEntry.getEvent()));

        return details.toString();
    }
}
