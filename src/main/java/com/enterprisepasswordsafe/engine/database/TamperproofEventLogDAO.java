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

package com.enterprisepasswordsafe.engine.database;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import com.enterprisepasswordsafe.engine.database.derived.UserSummary;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;
import com.enterprisepasswordsafe.proguard.ExternalInterface;
import com.enterprisepasswordsafe.proguard.JavaBean;

/**
 * Data access object for the tamperproof event logs.
 *
 * @author Compaq_Owner
 */

public class TamperproofEventLogDAO
	implements ExternalInterface {

	/**
	 * The human readable date format.
	 */

	private static final String DATE_FORMAT = "dd MMM yyyy '-' HH:mm:ss";

    /**
     * SQL Statement to get all the log entries for a given date.
     */

    private static final String GET_BY_DATE_RANGE_SQL =
        	"SELECT evl.dt_l, evl.user_id, evl.item_id, evl.event, evl.stamp_b, usr.user_name, pass.password_data, pass.history_stored"
            + "  FROM event_log evl "
            + "  LEFT OUTER JOIN application_users usr ON evl.user_id = usr.user_id"
            + "  LEFT OUTER JOIN passwords pass        ON evl.item_id = pass.password_id"
            + " WHERE evl.dt_l >= ? "
            + "   AND evl.dt_l <= ? "
            + " ORDER BY evl.dt_l ASC";

    /**
     * SQL Statement to get all the log entries for a given date for a given
     * user.
     */

    private static final String GET_BY_DATE_RANGE_AND_USER_SQL =
              "SELECT evl.dt_l, evl.user_id, evl.item_id, evl.event, evl.stamp_b, usr.user_name, pass.password_data, pass.history_stored"
            + "  FROM event_log evl "
            + "  LEFT OUTER JOIN application_users usr ON evl.user_id = usr.user_id"
            + "  LEFT OUTER JOIN passwords pass        ON evl.item_id = pass.password_id"
            + " WHERE evl.dt_l >= ? "
            + "   AND evl.dt_l <= ? "
            + "   AND evl.user_id = ? "
            + " ORDER BY evl.dt_l ASC";

    /**
     * SQL Statement to get all the log entries for a given date for a given
     * item.
     */

    private static final String GET_BY_DATE_RANGE_AND_ITEM_SQL =
    		  "SELECT evl.dt_l, evl.user_id, evl.item_id, evl.event, evl.stamp_b, usr.user_name, pass.password_data, pass.history_stored"
            + "  FROM event_log evl"
            + "  LEFT OUTER JOIN application_users usr ON evl.user_id = usr.user_id"
            + "  LEFT OUTER JOIN passwords pass        ON evl.item_id = pass.password_id"
            + " WHERE evl.dt_l >= ? "
            + "   AND evl.dt_l <= ? "
            + "   AND evl.item_id = ? "
            + " ORDER BY evl.datetime ASC";

    /**
     * SQL Statement to get all the log entries for a given date for a given
     * user.
     */

    private static final String GET_BY_DATE_RANGE_AND_USER_AND_ITEM_SQL =
		    "SELECT evl.dt_l, evl.user_id, evl.item_id, evl.event, evl.stamp_b, usr.user_name, pass.password_data, pass.history_stored"
            + "  FROM event_log evl "
            + "  LEFT OUTER JOIN application_users usr ON evl.user_id = usr.user_id"
            + "  LEFT OUTER JOIN passwords pass        ON evl.item_id = pass.password_id"
            + " WHERE evl.dt_l >= ? "
            + "   AND evl.dt_l <= ? "
            + "   AND evl.user_id = ? "
            + "   AND evl.item_id = ? "
            + " ORDER BY evl.datetime ASC";

    /**
     * SQL statement to write the event to the log.
     */

    private static final String WRITE_SQL =
              "INSERT INTO event_log(dt_l, item_id, event, user_id, stamp_b) "
            + "              VALUES (   ?,      ?,      ?,       ?,     ?)";

	/**
	 * Private constructor to prevent instantiation.
	 */

	private TamperproofEventLogDAO( ) {
		super();
	}

	/**
	 * Create a new log entry.
	 *
	 * @param theUser The user who caused the event.
	 * @param message The message to be logged.
	 * @param createTamperstamp Whether or not a tamperstamp should be created.
	 *
	 * @throws SQLException
	 * @throws GeneralSecurityException
	 * @throws UnsupportedEncodingException
	 */

	public void create( final User theUser, final AccessControledObject item,
						final String message, final boolean createTamperstamp,
						final String logLevel, final boolean sendEmail)
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		if(item != null && !item.isLoggable()) {
			return;
		}

		TamperproofEventLog event = new TamperproofEventLog(theUser, item, message, createTamperstamp);
		write(logLevel, event, item, sendEmail);
	}

	/**
	 * Create a new log entry.
	 *
     * @param logLevel The log level this message should be logged with.
	 * @param theUser The user who caused the event.
     * @param item The item associated with this event.
	 * @param message The message to be logged.
     * @param sendEmail Whether or not to send an email for the event.
	 *
	 * @throws SQLException
	 * @throws GeneralSecurityException
	 * @throws UnsupportedEncodingException
	 */

	public void create( final String logLevel, final User theUser, final AccessControledObject item,
						final String message, final boolean sendEmail )
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		create(theUser, item, message, true, logLevel, sendEmail);
	}

	/**
	 * Create a new log entry.
	 *
     * @param logLevel The log level this message should be logged with.
	 * @param theUser The user who caused the event.
	 * @param message The message to be logged.
	 * @param createTamperstamp Whether or not a tamperstamp should be created.
	 *
	 * @throws SQLException
	 * @throws GeneralSecurityException
	 * @throws UnsupportedEncodingException
	 */

	public void create( final String logLevel, final User theUser, final String message,
			final boolean createTamperstamp )
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		create(theUser, null, message, createTamperstamp, logLevel, true);
	}

	/**
	 * Create a new log entry.
	 *
     * @param logLevel The log level this message should be logged with.
	 * @param theUser The user who caused the event.
	 * @param message The message to be logged.
	 *
	 * @throws SQLException
	 * @throws GeneralSecurityException
	 * @throws UnsupportedEncodingException
	 */

	public void create( String logLevel, final User theUser, final String message )
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		create(theUser, null, message, true, logLevel, true);
	}

    /**
     * Calculates the string to replace a variable with (e.g. user:0 will be
     * replaced with "admin".
     *
     * @param variable The value to replace.
     *
     * @return The value to replace the variable with.
     *
     * @throws SQLException Thrown if there are problems retrieving the information.
     */

    private String valueOfToken(final String variable)
            throws SQLException {
        int colonIdx = variable.indexOf(':');
        if (colonIdx == -1) {
            return variable;
        }

        String variableType = variable.substring(0, colonIdx);
        String variableId = variable.substring(colonIdx + 1);

        if (variableType.equals("user")) {
            UserSummary theUser = UserDAO.getInstance().getSummaryById(variableId);
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

    /**
     * Gets the event message with any special references parsed out (e.g.
     * {user:0} replaced with the user name "admin".
     *
     * @param event The event message to expand.
     *
     * @return The message correctly parsed
     *
     * @throws SQLException Thrown if there is a problem retrieving the information.
     */

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

    private void sendEmail(final String logLevel, final TamperproofEventLog eventLogEntry,
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

        String smtpHost = ConfigurationDAO.getValue(ConfigurationOption.SMTP_HOST);
        String sender = ConfigurationDAO.getValue(ConfigurationOption.SMTP_FROM);

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

        Properties props = new Properties();
        props.put("mail.smtp.host", smtpHost);
        Session s = Session.getInstance(props, null);

        MimeMessage message = new MimeMessage(s);

        InternetAddress from = new InternetAddress(sender);
        message.setFrom(from);

        StringTokenizer recipientTokenizer = new StringTokenizer(recipient, ";");
        while (recipientTokenizer.hasMoreTokens()) {
            InternetAddress to = new InternetAddress(recipientTokenizer
                    .nextToken());
            message.addRecipient(Message.RecipientType.TO, to);
        }

        message.setSubject(getParsedMessage(eventLogEntry.getEvent()));
        message.setText(getFullMessage(eventLogEntry, item));

        Transport.send(message);
    }

    /**
     * Write a log entry to the log.
     *
     * @param logLevel The log level for the event.
     * @param eventLogEntry The entry to write.
     *
     * @throws SQLException Thrown if there is a storing retrieving the information.
     * @throws GeneralSecurityException thrown if there is a problem encrypting/decrypting data.
     * @throws UnsupportedEncodingException
     */

    private void write(final String logLevel, TamperproofEventLog eventLogEntry,
    		final AccessControledObject item, boolean sendEmail)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        String userId = eventLogEntry.getUserId();
        if (userId == null) {
        	userId = TamperproofEventLog.DUMMY_USER_ID;
        }

        PreparedStatement ps = null;
        try {
            ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_SQL);

            if (sendEmail) {
            	String sendEmails = ConfigurationDAO.getValue(ConfigurationOption.SMTP_ENABLED + "." + logLevel, null);
            	if(sendEmails == null || sendEmails.charAt(0) != 'N') {
	                try {
	                    sendEmail(logLevel, eventLogEntry, item);
	                } catch (Exception ex) {
	                    TamperproofEventLog log = new TamperproofEventLog(
	            				null,
	            				null,
	                            "Unable to send audit Email (Reason:"+ex.getMessage()+")",
	                            false
	                        );
	                    int idx = 1;
	                    ps.setLong(idx++, log.getDateTime());
	                    ps.setString(idx++, log.getItemId());
	                    ps.setString(idx++, log.getEvent());
	                    ps.setString(idx++, TamperproofEventLog.DUMMY_USER_ID);
	                    ps.setBytes(idx, log.getTamperStamp());

	                    ps.executeUpdate();
	                }
            	}
            }

            int idx = 1;
            ps.setLong(idx++, eventLogEntry.getDateTime());
            ps.setString(idx++, eventLogEntry.getItemId());
            ps.setString(idx++, eventLogEntry.getEvent());
            ps.setString(idx++, userId);
            ps.setBytes(idx, eventLogEntry.getTamperStamp());
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Checks to see and events tamperstamp is valid.
     *
     * @param eventLogEntry The entry to validate.
     * @param validatingUser The user attempting to validate the tamperstamp.
     *
     * @return true if the tamperstamp is valid, false if not.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws UnsupportedEncodingException
     */

    public boolean validateTamperstamp(TamperproofEventLog eventLogEntry, final User validatingUser)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {

    	User eventUser = null;
        if (!eventLogEntry.getUserId().equals(TamperproofEventLog.DUMMY_USER_ID)) {
            Group adminGroup = GroupDAO.getInstance().getAdminGroup(validatingUser);
            eventUser = UserDAO.getInstance().getById(eventLogEntry.getUserId());
            eventUser.decryptAdminAccessKey(adminGroup);
        }

        byte[] calculatedTamperstamp = eventLogEntry.createTamperstamp(eventUser);
        byte[] tamperStamp = eventLogEntry.getTamperStamp();
        return Arrays.equals(tamperStamp, calculatedTamperstamp);
    }

    /**
     * Create a tamperstamp.
     *
     * @param datetime The timestamp for the event.
     * @param event The test for the event.
     * @param itemId The ID of the item involved in the event.
     * @param userId The ID of the user involved in the event.
     */

    public static String createTamperstampString(final long datetime, final String event,
    		final String itemId, final String userId) {
        StringBuilder dataToCheck = new StringBuilder();
        dataToCheck.append(datetime);
        dataToCheck.append(event);
        if (itemId != null) {
            dataToCheck.append(itemId);
        }
        if (userId != null) {
            dataToCheck.append(userId);
        }

        return dataToCheck.toString();
    }

    /**
     * Gets the events relevant to the criteria supplied.
     *
     * @param startDate The start date for reporting.
     * @param endDate The end date for reporting.
     * @param userIdLimit The user ID to limit the report to (null means do not limit).
     * @param itemIdLimit The item ID to limit the report to (null means do not limit).
     * @param fetchingUser The user trying to get the events.
     * @param includePersonal Whether or not to include personal events.
     * @param validateTamperstamp Whether or not to validate the tamperstamp on the entries.
     *
     * @return a list of EventsForDay objects.
     *
     * @throws SQLException Thrown if there is a storing retrieving the information.
     * @throws GeneralSecurityException Thrown if there is a problem with the tamperstamp.
     * @throws UnsupportedEncodingException Thrown if there is a problem with the tamperstamp.
     */

    public List<EventsForDay> getEventsForDateRange(final long startDate,
            final long endDate, final String userIdLimit, final String itemIdLimit,
            final User fetchingUser, final boolean includePersonal,
            final boolean validateTamperstamp)
            throws 	SQLException,
            		UnsupportedEncodingException,
            		GeneralSecurityException {
    	Group adminGroup = GroupDAO.getInstance().getAdminGroup(fetchingUser);
        List<EventsForDay> events = new ArrayList<>();

        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            String sql = GET_BY_DATE_RANGE_SQL;
            if (userIdLimit != null && itemIdLimit != null) {
                sql = GET_BY_DATE_RANGE_AND_USER_AND_ITEM_SQL;
            } else if (userIdLimit != null) {
                sql = GET_BY_DATE_RANGE_AND_USER_SQL;
            } else if (itemIdLimit != null) {
                sql = GET_BY_DATE_RANGE_AND_ITEM_SQL;
            }

            int idx = 1;
            ps = BOMFactory.getCurrentConntection().prepareStatement(sql);
            ps.setLong(idx++, startDate);
            ps.setLong(idx++, endDate);

            if (userIdLimit != null) {
                ps.setString(idx++, userIdLimit);
            }
            if (itemIdLimit != null) {
                ps.setString(idx, itemIdLimit);
            }

            rs = ps.executeQuery();

            Map<String,User> userCache = new HashMap<>();
            List<ExpandedTamperproofEventLogEntry> daysEvents = new ArrayList<>();
            long currentDate = Long.MIN_VALUE;
            while (rs.next()) {
                long newDate = DateFormatter.stripTime(rs.getLong(1));
                if( currentDate != Long.MIN_VALUE && currentDate != newDate) {
                	EventsForDay eventsForDay = new EventsForDay(currentDate, daysEvents);
                	events.add(eventsForDay);
                	daysEvents = new ArrayList<>();
                }
                String itemId = rs.getString(3);
                if( !includePersonal
                && (rs.wasNull() || itemId == null)
                && HierarchyNodeDAO.getInstance().isPersonalByName(itemId)) {
                	continue;
                }

                daysEvents.add(
                		new ExpandedTamperproofEventLogEntry(
                				rs,
                				fetchingUser,
                				adminGroup,
                				validateTamperstamp,
                				userCache
                			)
            		);
                currentDate = newDate;
            }

            if( daysEvents.size() > 0 ) {
            	EventsForDay eventsForDay = new EventsForDay(currentDate, daysEvents);
            	events.add(eventsForDay);
            }
        } finally {
            DatabaseConnectionUtils.close(rs);
            DatabaseConnectionUtils.close(ps);
        }

        return events;
    }

    /**
     * Class holding a list of events for a specific day.
     */

    public static class EventsForDay
        implements JavaBean {
    	private final String humanReadableDate;
    	private final List<ExpandedTamperproofEventLogEntry> events;

    	public EventsForDay( final long date, final List<ExpandedTamperproofEventLogEntry> newEvents ) {
    		humanReadableDate = DateFormatter.convertToString(date);
    		events = newEvents;
    	}

		public List<ExpandedTamperproofEventLogEntry> getEvents() {
			return events;
		}

		public String getHumanReadableDate() {
			return humanReadableDate;
		}
    }

    private static final class InstanceHolder {
        private static final TamperproofEventLogDAO INSTANCE = new TamperproofEventLogDAO();
    }

    public static TamperproofEventLogDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
