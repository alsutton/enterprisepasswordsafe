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
import java.util.*;

import com.enterprisepasswordsafe.engine.hierarchy.HierarchyTools;
import com.enterprisepasswordsafe.engine.logging.LogEventHasher;
import com.enterprisepasswordsafe.engine.logging.LogEventMailer;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;

public class TamperproofEventLogDAO {

    private static final String GET_BY_DATE_RANGE_SQL =
        	"SELECT evl.dt_l, evl.user_id, evl.item_id, evl.event, evl.stamp_b, usr.user_name, pass.password_data, pass.history_stored"
            + "  FROM event_log evl "
            + "  LEFT OUTER JOIN application_users usr ON evl.user_id = usr.user_id"
            + "  LEFT OUTER JOIN passwords pass        ON evl.item_id = pass.password_id"
            + " WHERE evl.dt_l >= ? AND evl.dt_l <= ? ORDER BY evl.dt_l ASC";

    private static final String GET_BY_DATE_RANGE_AND_USER_SQL =
              "SELECT evl.dt_l, evl.user_id, evl.item_id, evl.event, evl.stamp_b, usr.user_name, pass.password_data, pass.history_stored"
            + "  FROM event_log evl "
            + "  LEFT OUTER JOIN application_users usr ON evl.user_id = usr.user_id"
            + "  LEFT OUTER JOIN passwords pass        ON evl.item_id = pass.password_id"
            + " WHERE evl.dt_l >= ? AND evl.dt_l <= ? AND evl.user_id = ? ORDER BY evl.dt_l ASC";

    private static final String GET_BY_DATE_RANGE_AND_ITEM_SQL =
    		  "SELECT evl.dt_l, evl.user_id, evl.item_id, evl.event, evl.stamp_b, usr.user_name, pass.password_data, pass.history_stored"
            + "  FROM event_log evl"
            + "  LEFT OUTER JOIN application_users usr ON evl.user_id = usr.user_id"
            + "  LEFT OUTER JOIN passwords pass        ON evl.item_id = pass.password_id"
            + " WHERE evl.dt_l >= ? AND evl.dt_l <= ? AND evl.item_id = ? ORDER BY evl.datetime ASC";

    private static final String GET_BY_DATE_RANGE_AND_USER_AND_ITEM_SQL =
		    "SELECT evl.dt_l, evl.user_id, evl.item_id, evl.event, evl.stamp_b, usr.user_name, pass.password_data, pass.history_stored"
            + "  FROM event_log evl "
            + "  LEFT OUTER JOIN application_users usr ON evl.user_id = usr.user_id"
            + "  LEFT OUTER JOIN passwords pass        ON evl.item_id = pass.password_id"
            + " WHERE evl.dt_l >= ? AND evl.dt_l <= ? AND evl.user_id = ? AND evl.item_id = ? ORDER BY evl.datetime ASC";

    private static final String WRITE_SQL =
              "INSERT INTO event_log(dt_l, item_id, event, user_id, stamp_b) VALUES (?, ?, ?, ?, ?)";

    private HierarchyTools hierarchyTools;

	private TamperproofEventLogDAO( ) {
		super();
		hierarchyTools = new HierarchyTools();
	}

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

	public void create( final String logLevel, final User theUser, final AccessControledObject item,
						final String message, final boolean sendEmail )
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		create(theUser, item, message, true, logLevel, sendEmail);
	}

	public void create( final String logLevel, final User theUser, final String message,
			final boolean createTamperstamp )
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		create(theUser, null, message, createTamperstamp, logLevel, true);
	}

	public void create( String logLevel, final User theUser, final String message )
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		create(theUser, null, message, true, logLevel, true);
	}

    private void write(final String logLevel, TamperproofEventLog eventLogEntry,
    		final AccessControledObject item, boolean sendEmail)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        String userId = eventLogEntry.getUserId();
        if (userId == null) {
        	userId = TamperproofEventLog.DUMMY_USER_ID;
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_SQL)) {
            if (sendEmail) {
                sendEmail(ps, logLevel, eventLogEntry, item);
            }
            writeEntry(ps, userId, eventLogEntry);
        }
    }

    private void sendEmail(final PreparedStatement writePreparedStatement, final String logLevel,
                           TamperproofEventLog eventLogEntry, final AccessControledObject item )
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        String sendEmails = ConfigurationDAO.getValue(
                        ConfigurationOption.SMTP_ENABLED + "." + logLevel, null);
        if(sendEmails == null || sendEmails.charAt(0) != 'N') {
            try {
                new LogEventMailer().sendEmail(logLevel, eventLogEntry, item);
            } catch (Exception ex) {
                TamperproofEventLog log = new TamperproofEventLog(null,null,
                        "Unable to send audit Email (Reason:"+ex.getMessage()+")",
                        false);
                writeEntry(writePreparedStatement, TamperproofEventLog.DUMMY_USER_ID, log);
            }
        }
    }

    private void writeEntry(PreparedStatement ps, String userId, TamperproofEventLog eventLogEntry)
            throws SQLException {
        ps.setLong(1, eventLogEntry.getDateTime());
        ps.setString(2, eventLogEntry.getItemId());
        ps.setString(3, eventLogEntry.getEvent());
        ps.setString(4, userId);
        ps.setBytes(5, eventLogEntry.getTamperStamp());
        ps.executeUpdate();
    }


    public boolean validateTamperstamp(TamperproofEventLog eventLogEntry, final User validatingUser)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {

    	User eventUser = null;
        if (!eventLogEntry.getUserId().equals(TamperproofEventLog.DUMMY_USER_ID)) {
            Group adminGroup = GroupDAO.getInstance().getAdminGroup(validatingUser);
            eventUser = UserDAO.getInstance().getById(eventLogEntry.getUserId());
            eventUser.decryptAdminAccessKey(adminGroup);
        }

        byte[] calculatedTamperstamp = new LogEventHasher().createTamperstamp(eventUser, eventLogEntry);
        byte[] tamperStamp = eventLogEntry.getTamperStamp();
        return Arrays.equals(tamperStamp, calculatedTamperstamp);
    }

    public List<EventsForDay> getEventsForDateRange(final long startDate,
            final long endDate, final String userIdLimit, final String itemIdLimit,
            final User fetchingUser, final boolean includePersonal,
            final boolean validateTamperstamp)
            throws 	SQLException,
            		UnsupportedEncodingException,
            		GeneralSecurityException {
    	Group adminGroup = GroupDAO.getInstance().getAdminGroup(fetchingUser);

        try (PreparedStatement ps =
                     BOMFactory.getCurrentConntection().prepareStatement(getSQLStatement(userIdLimit, itemIdLimit))) {
            int idx = 1;
            ps.setLong(idx++, startDate);
            ps.setLong(idx++, endDate);

            if (userIdLimit != null) {
                ps.setString(idx++, userIdLimit);
            }
            if (itemIdLimit != null) {
                ps.setString(idx, itemIdLimit);
            }

            try (ResultSet rs = ps.executeQuery()) {
                return processResults(rs, fetchingUser, adminGroup, includePersonal, validateTamperstamp);
            }
        }
    }

    private String getSQLStatement(final String userIdLimit, final String itemIdLimit) {
        String sql;
        if (userIdLimit != null && itemIdLimit != null) {
            sql = GET_BY_DATE_RANGE_AND_USER_AND_ITEM_SQL;
        } else if (userIdLimit != null) {
            sql = GET_BY_DATE_RANGE_AND_USER_SQL;
        } else if (itemIdLimit != null) {
            sql = GET_BY_DATE_RANGE_AND_ITEM_SQL;
        } else {
            sql = GET_BY_DATE_RANGE_SQL;
        }
        return sql;
    }

    private List<EventsForDay> processResults(final ResultSet rs, User fetchingUser, Group adminGroup,
                                             final boolean includePersonal, final boolean validateTamperstamp)
            throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
        List<EventsForDay> events = new ArrayList<>();

        List<ExpandedTamperproofEventLogEntry> daysEvents = new ArrayList<>();
        long currentDate = Long.MIN_VALUE;
        while (rs.next()) {
            long newDate = DateFormatter.stripTime(rs.getLong(1));
            if (currentDate != Long.MIN_VALUE && currentDate != newDate) {
                EventsForDay eventsForDay = new EventsForDay(currentDate, daysEvents);
                events.add(eventsForDay);
                daysEvents = new ArrayList<>();
            }

            processResult(rs, daysEvents, fetchingUser, adminGroup, includePersonal, validateTamperstamp);

            currentDate = newDate;
        }

        if (daysEvents.size() > 0) {
            EventsForDay eventsForDay = new EventsForDay(currentDate, daysEvents);
            events.add(eventsForDay);
        }

        return events;
    }

    private void processResult(ResultSet rs, List<ExpandedTamperproofEventLogEntry> daysEvents, User fetchingUser,
                               Group adminGroup, final boolean includePersonal, final boolean validateTamperstamp)
            throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
        String itemId = rs.getString(3);
        if (!includePersonal && (rs.wasNull() || itemId == null) && hierarchyTools.isPersonalByName(itemId)) {
            return;
        }

        daysEvents.add( ExpandedTamperproofEventLogEntry.from( rs, fetchingUser, adminGroup, validateTamperstamp));
    }

    public static class EventsForDay {
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
