package com.enterprisepasswordsafe.logging;

import com.enterprisepasswordsafe.model.AccessControledObject;
import com.enterprisepasswordsafe.model.ConfigurationOptions;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.LogEventClass;
import com.enterprisepasswordsafe.model.dao.ConfigurationDAO;
import com.enterprisepasswordsafe.model.persisted.LogEntry;
import com.enterprisepasswordsafe.model.persisted.User;

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

    private final LogEventParser logEventParser;
    private final ConfigurationDAO configurationDAO;

    public LogEventMailer(DAORepository daoRepository) {
        logEventParser = new LogEventParser(daoRepository);
        configurationDAO = daoRepository.getConfigurationDAO();
    }

    public LogEventMailer(DAORepository daoRepository, LogEventParser logEventParser) {
        this.logEventParser = logEventParser;
        configurationDAO = daoRepository.getConfigurationDAO();
    }

    /**
     * Sends an Email to to register an event.
     *
     * @param eventLogEntry The log entry to email a message for.
     *
     * @throws SQLException Thrown if there is a storing retrieving the information.
     * @throws AddressException Thrown if there is a problem sending the event Email.
     * @throws MessagingException Thrown if there is a problem sending the event Email.
     */

    public void sendEmail(final LogEntry eventLogEntry)
            throws SQLException, MessagingException {
        // Check email has been enabled
        String emailProperty = LogEventClass.getEmailPropertyFor(eventLogEntry.getLogEventClass());
        String smtpEnabled = configurationDAO.get(emailProperty);
        if (smtpEnabled == null) {
            smtpEnabled = configurationDAO.get(ConfigurationOptions.SMTP_ENABLED);
            if( smtpEnabled.charAt(0) == 'N') {
                return;
            }
        }

        Transport.send(constructMessage(eventLogEntry));
    }

    private MimeMessage constructMessage(final LogEntry eventLogEntry)
            throws SQLException, MessagingException {
        Properties props = new Properties();
        props.put("mail.smtp.host", configurationDAO.get(ConfigurationOptions.SMTP_HOST));
        Session s = Session.getInstance(props, null);

        MimeMessage message = new MimeMessage(s);

        InternetAddress from = new InternetAddress(configurationDAO.get(ConfigurationOptions.SMTP_FROM));
        message.setFrom(from);

        String recipient = determineRecipients(eventLogEntry);
        StringTokenizer recipientTokenizer = new StringTokenizer(recipient, ";");
        while (recipientTokenizer.hasMoreTokens()) {
            InternetAddress to = new InternetAddress(recipientTokenizer.nextToken());
            message.addRecipient(Message.RecipientType.TO, to);
        }

        message.setSubject(logEventParser.getParsedMessage(eventLogEntry.getEvent()));
        message.setText(logEventParser.getFullMessage(eventLogEntry));

        return message;
    }

    private String determineRecipients(final LogEntry eventLogEntry) {
        String recipient = configurationDAO.get(ConfigurationOptions.SMTP_TO_PROPERTY);
        String includeUser = configurationDAO.get(ConfigurationOptions.INCLUDE_USER_ON_AUDIT_EMAIL);
        if (includeUser != null && includeUser.equalsIgnoreCase("Y")) {
            User theUser = eventLogEntry.getUser();
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
