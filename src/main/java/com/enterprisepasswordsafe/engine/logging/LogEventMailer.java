package com.enterprisepasswordsafe.engine.logging;

import com.enterprisepasswordsafe.engine.database.*;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.sql.SQLException;
import java.util.Properties;
import java.util.StringTokenizer;

public class LogEventMailer {

    private LogEventParser logEventParser;

    public LogEventMailer() {
        logEventParser = new LogEventParser();
    }

    public LogEventMailer(LogEventParser logEventParser) {
        this.logEventParser = logEventParser;
    }

    /**
     * Sends an Email to to register an event.
     *
     * @param logLevel The log level for the event.
     * @param eventLogEntry The log entry to email a message for.
     * @param item The item relating to the event log entry.
     *
     * @throws SQLException Thrown if there is a storing retrieving the information.
     * @throws AddressException Thrown if there is a problem sending the event Email.
     * @throws MessagingException Thrown if there is a problem sending the event Email.
     */

    public void sendEmail(final String logLevel, final TamperproofEventLog eventLogEntry,
                           final AccessControledObject item)
            throws SQLException, MessagingException {
        // Check email has been enabled
        StringBuilder emailProperty = new StringBuilder(ConfigurationOption.SMTP_ENABLED.getPropertyName());
        if( logLevel != null ) {
            emailProperty.append('.');
            emailProperty.append(logLevel);
        }
        String smtpEnabled = ConfigurationDAO.getValue(emailProperty.toString(), null);
        if (smtpEnabled == null) {
            smtpEnabled = ConfigurationDAO.getValue(ConfigurationOption.SMTP_ENABLED);
            if( smtpEnabled.charAt(0) == 'N') {
                return;
            }
        }

        Transport.send(constructMessage(eventLogEntry, item));
    }

    private MimeMessage constructMessage(final TamperproofEventLog eventLogEntry,
                                         final AccessControledObject item)
            throws SQLException, MessagingException {
        Properties props = new Properties();
        props.put("mail.smtp.host", ConfigurationDAO.getValue(ConfigurationOption.SMTP_HOST));
        Session s = Session.getInstance(props, null);

        MimeMessage message = new MimeMessage(s);

        InternetAddress from = new InternetAddress(ConfigurationDAO.getValue(ConfigurationOption.SMTP_FROM));
        message.setFrom(from);

        String recipient = determineRecipients(eventLogEntry);
        StringTokenizer recipientTokenizer = new StringTokenizer(recipient, ";");
        while (recipientTokenizer.hasMoreTokens()) {
            InternetAddress to = new InternetAddress(recipientTokenizer.nextToken());
            message.addRecipient(Message.RecipientType.TO, to);
        }

        message.setSubject(logEventParser.getParsedMessage(eventLogEntry.getEvent()));
        message.setText(logEventParser.getFullMessage(eventLogEntry, item));

        return message;
    }

    private String determineRecipients(final TamperproofEventLog eventLogEntry)
            throws SQLException {
        String recipient = ConfigurationDAO.getValue(ConfigurationOption.SMTP_TO_PROPERTY);
        String includeUser = ConfigurationDAO.getValue(ConfigurationOption.INCLUDE_USER_ON_AUDIT_EMAIL);
        if (includeUser != null && includeUser.equalsIgnoreCase("Y")) {
            User theUser = UserDAO.getInstance().getById(eventLogEntry.getUserId());
            if (theUser != null ) {
                String userEmail = theUser.getEmail();
                if( userEmail != null && userEmail.length() > 0) {
                    StringBuilder newRecipient = new StringBuilder(recipient);
                    if (recipient.length() > 0) {
                        newRecipient.append("; ");
                    }
                    newRecipient.append(userEmail);
                    recipient = newRecipient.toString();
                }
            }
        }

        return recipient;
    }

}
