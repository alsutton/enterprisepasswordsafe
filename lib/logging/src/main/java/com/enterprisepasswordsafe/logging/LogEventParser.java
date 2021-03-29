package com.enterprisepasswordsafe.logging;

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.dao.HierarchyNodeDAO;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.LogEntry;
import com.enterprisepasswordsafe.model.persisted.User;

import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.StringTokenizer;

public class LogEventParser {
    private static final String DATE_FORMAT = "dd MMM yyyy '-' HH:mm:ss";

    private final DAORepository daoRepository;

    public LogEventParser(DAORepository daoRepository) {
        this.daoRepository = daoRepository;
    }

    private String valueOfToken(final String variable) {
        int colonIdx = variable.indexOf(':');
        if (colonIdx == -1) {
            return variable;
        }

        String variableType = variable.substring(0, colonIdx);
        String variableId = variable.substring(colonIdx + 1);
        Long idAsLong = Long.parseLong(variableId);

        if (variableType.equals("user")) {
            User theUser = daoRepository.getUserDAO().getById(idAsLong);
            if (theUser != null) {
                return theUser.getName();
            }

            return "user with the id " + variableId;
        }

        if (variableType.equals("group")) {
            Group theGroup = daoRepository.getGroupDAO().getById(idAsLong);
            if( theGroup != null ) {
                return theGroup.getName();
            }

            return "group with the id " + variableId;
        }

        if (variableType.equals("node")) {
            HierarchyNode theNode =
                    daoRepository.getHierarchyNodeDAO().getById(variableId);
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
     *
     * @return A textual description of the event.
     *
     * @throws SQLException Thrown if there is a storing retrieving the information.
     */

    public String getFullMessage(LogEntry eventLogEntry)
            throws SQLException {
        StringBuilder details = new StringBuilder(1024);

        // Format the date
        details.append("Date : ");
        Date datetime = eventLogEntry.getTimestamp();
        SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
        details.append(sdf.format(datetime));
        details.append('\n');

        // Add the user informtion
        User theUser = eventLogEntry.getUser();
        details.append("User : ");
        if (theUser != null) {
            details.append(theUser.getName());
        } else {
            details.append("<None>");
        }

        if( eventLogEntry.getItem() != null ) {
            details.append("\n");
            details.append("Object involved: ");
            details.append(eventLogEntry.getItem().toString());
        }

        details.append("\n\n");

        // Add the event
        details.append(getParsedMessage(eventLogEntry.getEvent()));

        return details.toString();
    }
}
