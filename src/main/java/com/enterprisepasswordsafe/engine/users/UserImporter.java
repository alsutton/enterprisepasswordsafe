package com.enterprisepasswordsafe.engine.users;

import com.enterprisepasswordsafe.engine.database.*;
import com.enterprisepasswordsafe.engine.database.derived.UserSummary;
import com.enterprisepasswordsafe.engine.utils.PasswordGenerator;
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

    private final UserDAO userDAO;
    private final UserPriviledgeTransitioner userPriviledgeTransitioner;

    public UserImporter(UserDAO userDAO, UserPriviledgeTransitioner userPriviledgeTransitioner) {
        this.userDAO = userDAO;
        this.userPriviledgeTransitioner = userPriviledgeTransitioner;
    }

    /**
     * Import a user line into the database. The format should be;<br/>
     * username[,password[.full_name[,email]]]<br/> If no password is
     * specified, one will be generated.
     *
     * @param theImporter The user performing the import.
     * @param adminGroup The adminGroup used to set the users type.
     * @param passwordGenerator The password generator to use if needed.
     * @param record The CSV record to import.
     *
     * @return The password used for the user
     */

    public String importData(final User theImporter, final Group adminGroup,
                             final PasswordGenerator passwordGenerator, CSVRecord record)
            throws SQLException, GeneralSecurityException, IOException, MessagingException {
        Iterator<String> values = record.iterator();
        if (!values.hasNext()) {
            return null;
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
        int userType = getUserTypeFromCSVRecord(values);
        boolean usePasswordGeneratorForLoginPassword = !values.hasNext();
        String password = usePasswordGeneratorForLoginPassword ? passwordGenerator.getRandomPassword() : values.next().trim();

        User createdUser = userDAO.createUser(theImporter, new UserSummary(username, fullname), password, email);

        performPostCreationActions(theImporter, adminGroup, createdUser, userType, usePasswordGeneratorForLoginPassword);

        sendUserCreationEmailToUserIfNeccessary(createdUser, password);

        return password;
    }

    private String getNextValueFromCSVRecordIterator(final Iterator<String> iterator, final String error )
            throws GeneralSecurityException {
        if (!iterator.hasNext()) {
            throw new GeneralSecurityException(error);
        }
        return iterator.next().trim();
    }

    private int getUserTypeFromCSVRecord(Iterator<String> values)
            throws GeneralSecurityException {
        if(!values.hasNext()) {
            return User.USER_TYPE_NORMAL;
        }

        String userTypeString = values.next().trim();
        if(userTypeString.isEmpty()) {
            return User.USER_TYPE_NORMAL;
        }

        switch(userTypeString.charAt(0)) {
            case 'E':
                return User.USER_TYPE_ADMIN;
            case 'P':
                return User.USER_TYPE_SUBADMIN;
            case 'N':
                return User.USER_TYPE_NORMAL;
            default:
                throw new GeneralSecurityException("User type unknown - "+userTypeString);
        }
    }

    private void performPostCreationActions(final User theImporter, final Group adminGroup,
                                            final User createdUser, int userType, boolean hasGeneratedPassword)
            throws SQLException, IOException, GeneralSecurityException {
        if( hasGeneratedPassword ) {
            createdUser.forcePasswordChangeAtNextLogin();
            userDAO.update(createdUser);
        }

        switch(userType) {
            case User.USER_TYPE_ADMIN:
                userPriviledgeTransitioner.makeAdmin(theImporter, adminGroup, createdUser);
                break;
            case User.USER_TYPE_SUBADMIN:
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

        String smtpHost = ConfigurationDAO.getValue(ConfigurationOption.SMTP_HOST);
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

        String smtpSenderString = ConfigurationDAO.getValue(ConfigurationOption.SMTP_FROM);
        MimeMessage mimeMessage = new MimeMessage(s);
        mimeMessage.setFrom(new InternetAddress(smtpSenderString));
        InternetAddress to = new InternetAddress(usersEmailAddress);
        mimeMessage.addRecipient(Message.RecipientType.TO, to);

        mimeMessage.setSubject("Enterprise Password Safe Account");
        mimeMessage.setText(message);

        Transport.send(mimeMessage);
    }
}
