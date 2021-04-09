package com.enterprisepasswordsafe.engine.users;

import com.enterprisepasswordsafe.database.*;
import com.enterprisepasswordsafe.database.derived.ImmutableUserSummary;
import com.enterprisepasswordsafe.engine.utils.PasswordGenerator;
import com.enterprisepasswordsafe.model.ConfigurationOptions;
import com.enterprisepasswordsafe.model.dao.ConfigurationDAO;
import com.enterprisepasswordsafe.model.dao.UserDAO;
import org.apache.commons.csv.CSVRecord;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Iterator;
import java.util.Properties;

public class UserImporter {

    public enum UserType { NORMAL, SUBADMIN, ADMIN }

    private final UserDAO userDAO;
    private final UserPriviledgeTransitioner userPriviledgeTransitioner;

    public UserImporter(UserDAO userDAO, UserPriviledgeTransitioner userPriviledgeTransitioner) {
        this.userDAO = userDAO;
        this.userPriviledgeTransitioner = userPriviledgeTransitioner;
    }

    public void importData(final User theImporter, final Group adminGroup,
                           final PasswordGenerator passwordGenerator, CSVRecord record)
            throws SQLException, GeneralSecurityException, IOException, MessagingException {
        Iterator<String> values = record.iterator();
        if (!values.hasNext()) {
            return;
        }

        String username = values.next().trim();
        String fullname =
                getNextValueFromCSVRecordIterator(
                        values,
                        "The user " + username + " does not have a full name specified.");
        String email =
                getNextValueFromCSVRecordIterator(
                        values,
                        "The user " + username + " does not have an email address specified.");
        UserType userType = getUserTypeFromCSVRecord(values);
        boolean usePasswordGeneratorForLoginPassword = !values.hasNext();
        String password = usePasswordGeneratorForLoginPassword ? passwordGenerator.getRandomPassword() : values.next().trim();

        User createdUser = userDAO.createUser(theImporter,
                ImmutableUserSummary.builder().name(username).fullName(fullname).build(),
                password,
                email);

        performPostCreationActions(theImporter, adminGroup, createdUser, userType, usePasswordGeneratorForLoginPassword);

        sendUserCreationEmailToUserIfNeccessary(createdUser, password);
    }

    private String getNextValueFromCSVRecordIterator(final Iterator<String> iterator, final String error )
            throws GeneralSecurityException {
        if (!iterator.hasNext()) {
            throw new GeneralSecurityException(error);
        }
        return iterator.next().trim();
    }

    private UserType getUserTypeFromCSVRecord(Iterator<String> values)
            throws GeneralSecurityException {
        if(!values.hasNext()) {
            return UserType.NORMAL;
        }

        String userTypeString = values.next().trim();
        if(userTypeString.isEmpty()) {
            return UserType.NORMAL;
        }

        switch(userTypeString.charAt(0)) {
            case 'E':
                return UserType.ADMIN;
            case 'P':
                return UserType.SUBADMIN;
            case 'N':
                return UserType.NORMAL;
            default:
                throw new GeneralSecurityException("User type unknown - "+userTypeString);
        }
    }

    private void performPostCreationActions(final User theImporter, final Group adminGroup,
                                            final User createdUser, UserType userType, boolean hasGeneratedPassword)
            throws SQLException, IOException, GeneralSecurityException {
        if( hasGeneratedPassword ) {
            createdUser.forcePasswordChangeAtNextLogin();
            userDAO.update(createdUser);
        }

        switch(userType) {
            case ADMIN:
                userPriviledgeTransitioner.makeAdmin(theImporter, adminGroup, createdUser);
                break;
            case SUBADMIN:
                userPriviledgeTransitioner.makeSubadmin(theImporter, adminGroup, createdUser);
                break;
        }
    }

    private void sendUserCreationEmailToUserIfNeccessary(User createdUser, String password)
            throws SQLException, MessagingException {
        String usersEmailAddress = createdUser.getEmail();
        if( usersEmailAddress == null || usersEmailAddress.isEmpty()) {
            return;
        }

        String smtpHost = ConfigurationDAO.getValue(ConfigurationOptions.SMTP_HOST);
        if(smtpHost == null || smtpHost.isEmpty()) {
            return;
        }

        String message =
                "Dear " + createdUser.getFullName() + "\n\n" +
                        "An account has been created for you in the Enterprise Password Safe\n" +
                        "with the credentials;\n\n" +
                        "Username : " + createdUser.getUserName() + "\n" +
                        "Password : " + password + "\n\n" +
                        "Please do not disclose this information to anyone else.";

        Properties props = new Properties();
        props.put("mail.smtp.host", smtpHost);
        Session s = Session.getInstance(props, null);

        String smtpSenderString = ConfigurationDAO.getValue(ConfigurationOptions.SMTP_FROM);
        MimeMessage mimeMessage = new MimeMessage(s);
        mimeMessage.setFrom(new InternetAddress(smtpSenderString));
        InternetAddress to = new InternetAddress(usersEmailAddress);
        mimeMessage.addRecipient(Message.RecipientType.TO, to);

        mimeMessage.setSubject("Enterprise Password Safe Account");
        mimeMessage.setText(message);

        Transport.send(mimeMessage);
    }
}
