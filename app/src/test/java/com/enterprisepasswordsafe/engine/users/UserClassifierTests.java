package com.enterprisepasswordsafe.engine.users;

import com.enterprisepasswordsafe.database.Group;
import com.enterprisepasswordsafe.database.MembershipDAO;
import com.enterprisepasswordsafe.database.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.sql.SQLException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class UserClassifierTests {

    private static final String TEST_USER_ID = "u1234test";

    @Mock
    MembershipDAO mockMembershipDAO;
    @Mock
    User mockUser;

    private UserClassifier instanceUnderTest;

    @BeforeEach
    public void setUp() {
        instanceUnderTest = new UserClassifier(mockMembershipDAO);
    }

    @Test
    public void testAdminUserIsDetectedFromStorage() throws SQLException {
        setUserIdOnMock();
        setUserAsAdmin();

        UserLevel level = instanceUnderTest.getUserLevelFor(mockUser);

        assertEquals(UserLevel.ADMINISTRATOR, level);
        assertTrue(instanceUnderTest.isAdministrator(mockUser));
        assertFalse(instanceUnderTest.isSubadministrator(mockUser));
        assertTrue(instanceUnderTest.isPriviledgedUser(mockUser));
    }

    @Test
    public void testAdminUserIsDetectedFromMap() {
        UserLevel level = instanceUnderTest.getUserLevelFrom(Map.of(Group.ADMIN_GROUP_ID, new Object()));

        assertEquals(UserLevel.ADMINISTRATOR, level);
    }

    @Test
    public void testPrivilegedUserIsDetectedFromStorage() throws SQLException {
        setUserIdOnMock();
        setUserAsPrivileged();

        UserLevel level = instanceUnderTest.getUserLevelFor(mockUser);

        assertEquals(UserLevel.PRIVILEGED, level);
        assertFalse(instanceUnderTest.isAdministrator(mockUser));
        assertTrue(instanceUnderTest.isSubadministrator(mockUser));
        assertTrue(instanceUnderTest.isPriviledgedUser(mockUser));
    }

    @Test
    public void testPrivilegedUserIsDetectedFromMap() {
        UserLevel level = instanceUnderTest.getUserLevelFrom(Map.of(Group.SUBADMIN_GROUP_ID, new Object()));

        assertEquals(UserLevel.PRIVILEGED, level);
    }

    @Test
    public void testRegularUserIsDetectedFromStorage() throws SQLException {
        UserLevel level = instanceUnderTest.getUserLevelFor(mockUser);

        assertEquals(UserLevel.REGULAR, level);
        assertFalse(instanceUnderTest.isAdministrator(mockUser));
        assertFalse(instanceUnderTest.isSubadministrator(mockUser));
        assertFalse(instanceUnderTest.isPriviledgedUser(mockUser));
    }
    @Test
    public void testRegularUserIsDetectedFromMap() {
        UserLevel level = instanceUnderTest.getUserLevelFrom(Map.of());

        assertEquals(UserLevel.REGULAR, level);
    }

    @Test
    public void testNonViewingUserIsDetectedFromStorage() throws SQLException {
        setUserIdOnMock();
        setUserAsNonViewing();

        assertTrue(instanceUnderTest.isNonViewingUser(mockUser));
    }

    @Test
    public void testViewingUserIsDetectedFromStorage() throws SQLException {
        when(mockUser.getId()).thenReturn(TEST_USER_ID);

        assertFalse(instanceUnderTest.isNonViewingUser(mockUser));
    }

    private void setUserAsAdmin() throws SQLException {
        when(mockMembershipDAO.isMemberOf(TEST_USER_ID, Group.ADMIN_GROUP_ID)).thenReturn(true);
    }

    private void setUserAsPrivileged() throws SQLException {
        when(mockMembershipDAO.isMemberOf(TEST_USER_ID, Group.ADMIN_GROUP_ID)).thenReturn(false);
        when(mockMembershipDAO.isMemberOf(TEST_USER_ID, Group.SUBADMIN_GROUP_ID)).thenReturn(true);
    }

    private void setUserAsNonViewing() throws SQLException {
        when(mockMembershipDAO.isMemberOf(TEST_USER_ID, Group.NON_VIEWING_GROUP_ID)).thenReturn(true);
    }

    private void setUserIdOnMock() {
        when(mockUser.getId()).thenReturn(TEST_USER_ID);
    }
}
