package com.enterprisepasswordsafe.engine.database;

import com.enterprisepasswordsafe.engine.logging.LogEventHasher;
import com.enterprisepasswordsafe.engine.logging.LogEventParser;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class ExpandedTamperproofEventLogEntryTests {

    private static final int TEST_YEAR = 1999;
    private static final int TEST_MONTH = Calendar.JUNE;
    private static final int TEST_DAY = 10;
    private static final int TEST_HOUR = 12;
    private static final int TEST_MINUTE = 30;
    private static final int TEST_SECOND = 45;

    private static final String TEST_USER_ID = "TEST_USER_ID";
    private static final String TEST_ITEM_ID = "TEST_ITEM_ID";
    private static final String TEST_EVENT = "Something happened";
    private static final String TEST_PARSED_EVENT = "Something really happened";
    private static final byte[] TEST_TAMPERSTAMP = {0x01, 0x02, 0x03, 0x0f};
    private static final String TEST_USERNAME = "TEST_USERNAME";

    private static final byte[] INVALID_TAMPERSTAMP = {0x01, 0x02, 0x04, 0x0f};

    private Calendar testTimestamp;
    private ResultSet resultSet;
    private User user;
    private Group adminGroup;
    private UserClassifier userClassifier;
    private LogEventHasher logEventHasher;
    private LogEventParser logEventParser;
    private AccessControlDAO accessControlDAO;
    private UserDAO userDAO;

    private ExpandedTamperproofEventLogEntry testInstance;

    @BeforeEach
    public void setUp() {
        testTimestamp = Calendar.getInstance();
        testTimestamp.set(TEST_YEAR, TEST_MONTH, TEST_DAY, TEST_HOUR, TEST_MINUTE, TEST_SECOND);

        resultSet = Mockito.mock(ResultSet.class);
        user = Mockito.mock(User.class);
        adminGroup = Mockito.mock(Group.class);

        userClassifier = Mockito.mock(UserClassifier.class);
        logEventHasher = Mockito.mock(LogEventHasher.class);
        logEventParser = Mockito.mock(LogEventParser.class);
        accessControlDAO = Mockito.mock(AccessControlDAO.class);
        userDAO = Mockito.mock(UserDAO.class);
    }

    @Test
    public void testDecodesDate() throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        createInstanceWithoutItem();

        Date date = testInstance.getDate();

        assertEquals(TEST_YEAR % 100, date.getYear()); // Dates are YY only
        assertEquals(TEST_MONTH, date.getMonth());
        assertEquals(TEST_DAY, date.getDate());
    }

    @Test
    public void testDecodesTime() throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        createInstanceWithoutItem();

        Date date = testInstance.getDate();

        assertEquals(TEST_HOUR, date.getHours());
        assertEquals(TEST_MINUTE, date.getMinutes());
        assertEquals(TEST_SECOND, date.getSeconds());
    }

    @Test
    public void testDecodesItemId() throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        createInstanceWithItem();

        assertEquals(TEST_ITEM_ID, testInstance.getItemId());
        verify(accessControlDAO).getReadAccessControl(eq(user), eq(TEST_ITEM_ID));
    }

    @Test
    public void testAttemptsToParseEvent() throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        when(logEventParser.getParsedMessage(eq(TEST_EVENT))).thenReturn(TEST_PARSED_EVENT);

        createInstanceWithItem();

        assertEquals(TEST_PARSED_EVENT, testInstance.toString());
        verify(logEventParser).getParsedMessage(eq(TEST_EVENT));
    }

    @Test
    public void testDetectsMissingTamperstamp() throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        createInstanceWithItem();

        assertEquals(ExpandedTamperproofEventLogEntry.Status.UNKNOWN, testInstance.getTamperstampStatus());
    }

    @Test
    public void testDetectsIncorrectTamperstamp() throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        when(logEventHasher.createTamperstamp(eq(user), anyLong(), eq(TEST_EVENT), eq(TEST_ITEM_ID), eq(TEST_USER_ID))).thenReturn(INVALID_TAMPERSTAMP);
        when(resultSet.getBytes(eq(5))).thenReturn(TEST_TAMPERSTAMP);

        createInstanceWithItem();

        assertEquals(ExpandedTamperproofEventLogEntry.Status.INVALID, testInstance.getTamperstampStatus());
    }

    @Test
    public void testDetectsCorrectTamperstamp() throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        when(logEventHasher.createTamperstamp(eq(user), anyLong(), eq(TEST_EVENT), eq(TEST_ITEM_ID), eq(TEST_USER_ID))).thenReturn(TEST_TAMPERSTAMP);
        when(resultSet.getBytes(eq(5))).thenReturn(TEST_TAMPERSTAMP);

        createInstanceWithItem();

        assertEquals(ExpandedTamperproofEventLogEntry.Status.OK, testInstance.getTamperstampStatus());
    }

    @Test
    public void testDecodesUsername() throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        createInstanceWithoutItem();

        assertEquals(TEST_USERNAME, testInstance.getUsername());
    }

    private void createInstanceWithoutItem() throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
        createInstance(null);
    }

    private void createInstanceWithItem() throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
        createInstance(TEST_ITEM_ID);
    }

    private void createInstance(String item) throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
        when(resultSet.getLong(eq(1))).thenReturn(testTimestamp.getTimeInMillis());
        when(resultSet.getString(eq(2))).thenReturn(TEST_USER_ID);
        when(resultSet.getString(eq(3))).thenReturn(item);
        when(resultSet.getString(eq(4))).thenReturn(TEST_EVENT);
        when(resultSet.getString(eq(6))).thenReturn(TEST_USERNAME);

        when(user.getId()).thenReturn(TEST_USER_ID);
        when(userDAO.getByIdDecrypted(eq(TEST_USER_ID), eq(adminGroup))).thenReturn(user);

        testInstance = new ExpandedTamperproofEventLogEntry(userClassifier, logEventHasher, logEventParser,
                accessControlDAO, userDAO, resultSet, user, adminGroup, true);
    }
}
