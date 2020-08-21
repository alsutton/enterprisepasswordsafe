package com.enterprisepasswordsafe.engine.passwords;

import com.enterprisepasswordsafe.database.Group;
import com.enterprisepasswordsafe.database.GroupAccessControlDAO;
import com.enterprisepasswordsafe.database.GroupDAO;
import com.enterprisepasswordsafe.database.HierarchyNodePermissionDAO;
import com.enterprisepasswordsafe.database.MembershipDAO;
import com.enterprisepasswordsafe.database.Password;
import com.enterprisepasswordsafe.database.PasswordDAO;
import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.database.UserAccessControlDAO;
import com.enterprisepasswordsafe.database.UserDAO;
import com.enterprisepasswordsafe.engine.accesscontrol.PasswordPermission;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class PasswordImporterTests {
    private static final String TEST_USERNAME = "username";
    private static final String TEST_LOCATION = "location";
    private static final String TEST_PASSWORD = "password";
    private static final String TEST_NOTES = "notes";
    private static final String TEST_PARENT_NODE = "0";

    private static final String TEST_LOGIN_ACCOUNT = "test_login";
    private static final String TEST_USER_GROUP = "test_group";

    @Mock
    User mockUser;
    @Mock
    Group mockAdminGroup;
    Password fakePassword;

    @Mock
    PasswordDAO mockPasswordDAO;
    @Mock
    UserDAO mockUserDAO;
    @Mock
    GroupDAO mockGroupDAO;
    @Mock
    MembershipDAO mockMembershipDAO;
    @Mock
    UserAccessControlDAO mockUserAccessControlDAO;
    @Mock
    GroupAccessControlDAO mockGroupAccessControlDAO;
    @Mock
    HierarchyNodePermissionDAO hierarchyNodePermissionDAO;

    private PasswordImporter instanceUnderTest;

    private static List<String> getTestData() {
        return List.of(TEST_LOCATION, TEST_USERNAME, TEST_PASSWORD, TEST_NOTES, "F", "True");
    }

    private static List<String> getTestData(String... additions) {
        List<String> testData = new ArrayList<>(getTestData());
        Collections.addAll(testData, additions);
        return testData;
    }

    @BeforeEach
    public void setUp() throws GeneralSecurityException, SQLException, IOException {
        fakePassword = new Password();
        instanceUnderTest = new PasswordImporter(mockPasswordDAO, mockUserDAO, mockGroupDAO, mockMembershipDAO,
                mockUserAccessControlDAO, mockGroupAccessControlDAO, hierarchyNodePermissionDAO);

        when(mockPasswordDAO.create(any(), any(), any(), any(), any(), any(), any(), anyBoolean(), anyLong(), any(),
                any(), anyBoolean(), anyInt(), anyInt(), anyInt(), any())).thenReturn(fakePassword);
    }

    @Test
    public void testDataIsImportedCorrectly() throws GeneralSecurityException, SQLException, IOException {
        instanceUnderTest.importPassword(mockUser, mockAdminGroup, TEST_PARENT_NODE, getTestData());

        verify(mockPasswordDAO).create(eq(mockUser), eq(mockAdminGroup), eq(TEST_USERNAME), eq(TEST_PASSWORD),
                eq(TEST_LOCATION), eq(TEST_NOTES), eq(AuditingLevel.FULL), eq(true), anyLong(),
                eq(TEST_PARENT_NODE), any(), anyBoolean(), anyInt(), anyInt(), eq(Password.TYPE_SYSTEM), any());
    }

    @Test
    public void testCustomFieldsAreImported() throws GeneralSecurityException, SQLException, IOException {
        instanceUnderTest.importPassword(mockUser, mockAdminGroup, TEST_PARENT_NODE, getTestData("CF:cf1=cv1"));

        assertEquals("cv1", fakePassword.getCustomField("cf1"));
    }

    @Test
    public void testUserModifyPermissionsAreImported() throws GeneralSecurityException, SQLException, IOException {
        User user = mock(User.class);
        when(mockUserDAO.getByName(eq(TEST_LOGIN_ACCOUNT))).thenReturn(user);

        instanceUnderTest.importPassword(mockUser, mockAdminGroup, TEST_PARENT_NODE,
                getTestData("UM:" + TEST_LOGIN_ACCOUNT));

        verify(mockUserAccessControlDAO).create(user, fakePassword, PasswordPermission.MODIFY);
    }

    @Test
    public void testUserReadOnlyPermissionsAreImported() throws GeneralSecurityException, SQLException, IOException {
        User user = mock(User.class);
        when(mockUserDAO.getByName(eq(TEST_LOGIN_ACCOUNT))).thenReturn(user);

        instanceUnderTest.importPassword(mockUser, mockAdminGroup, TEST_PARENT_NODE,
                getTestData("UV:" + TEST_LOGIN_ACCOUNT));

        verify(mockUserAccessControlDAO).create(user, fakePassword, PasswordPermission.READ);
    }

    @Test
    public void testUserPermissionForNonExistentUserFails() throws SQLException {
        when(mockUserDAO.getByName(eq(TEST_LOGIN_ACCOUNT))).thenReturn(null);

        assertThrows(GeneralSecurityException.class, () -> instanceUnderTest.importPassword(mockUser, mockAdminGroup,
                TEST_PARENT_NODE, getTestData("UV:" + TEST_LOGIN_ACCOUNT)));
    }

    @Test
    public void testGroupModifyPermissionsAreImported() throws GeneralSecurityException, SQLException, IOException {
        Group group = mock(Group.class);
        when(mockGroupDAO.getByName(eq(TEST_USER_GROUP))).thenReturn(group);

        instanceUnderTest.importPassword(mockUser, mockAdminGroup, TEST_PARENT_NODE,
                getTestData("GM:" + TEST_USER_GROUP));

        verify(mockGroupAccessControlDAO).create(group, fakePassword, PasswordPermission.MODIFY);
    }

    @Test
    public void testGroupReadOnlyPermissionsAreImported() throws GeneralSecurityException, SQLException, IOException {
        Group group = mock(Group.class);
        when(mockGroupDAO.getByName(eq(TEST_USER_GROUP))).thenReturn(group);

        instanceUnderTest.importPassword(mockUser, mockAdminGroup, TEST_PARENT_NODE,
                getTestData("GV:" + TEST_USER_GROUP));

        verify(mockGroupAccessControlDAO).create(group, fakePassword, PasswordPermission.READ);
    }

    @Test
    public void testGroupPermissionForNonExistentUserFails() throws SQLException {
        when(mockGroupDAO.getByName(eq(TEST_USER_GROUP))).thenReturn(null);

        assertThrows(GeneralSecurityException.class, () -> instanceUnderTest.importPassword(mockUser, mockAdminGroup,
                TEST_PARENT_NODE, getTestData("GV:" + TEST_USER_GROUP)));
    }


    @Test
    public void testGroupAndUserReadOnlyPermissionsAreImported() throws GeneralSecurityException, SQLException, IOException {
        Group group = mock(Group.class);
        when(mockGroupDAO.getByName(eq(TEST_USER_GROUP))).thenReturn(group);
        User user = mock(User.class);
        when(mockUserDAO.getByName(eq(TEST_LOGIN_ACCOUNT))).thenReturn(user);

        instanceUnderTest.importPassword(mockUser, mockAdminGroup, TEST_PARENT_NODE,
                getTestData("GV:" + TEST_USER_GROUP, "UV:" + TEST_LOGIN_ACCOUNT));

        verify(mockGroupAccessControlDAO).create(group, fakePassword, PasswordPermission.READ);
        verify(mockUserAccessControlDAO).create(user, fakePassword, PasswordPermission.READ);
    }
}
