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
import com.enterprisepasswordsafe.engine.accesscontrol.GroupAccessControl;
import com.enterprisepasswordsafe.engine.accesscontrol.PasswordPermission;
import com.enterprisepasswordsafe.engine.accesscontrol.UserAccessControl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class PasswordImporterTests {
    private static final String TEST_USERNAME = "username";
    private static final String TEST_LOCATION = "location";
    private static final String TEST_PASSWORD = "password";
    private static final String TEST_NOTES = "notes";
    private static final String TEST_PARENT_NODE = "0";

    private static final String TEST_LOGIN_ACCOUNT_ID = "u123";
    private static final String TEST_LOGIN_ACCOUNT = "test_login";
    private static final String TEST_USER_GROUP_ID = "g123";
    private static final String TEST_USER_GROUP = "test_group";

    @Mock
    User mockUser;
    @Mock
    Group mockAdminGroup;
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
    @Mock
    PublicKey mockReadKey;

    Password fakePassword;

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
                mockUserAccessControlDAO, mockGroupAccessControlDAO, hierarchyNodePermissionDAO, mockAdminGroup);

        when(mockPasswordDAO.create(any(), any(), any(), any(), any(), any(), any(), anyBoolean(), anyLong(), any(),
                any(), anyBoolean(), anyInt(), anyInt(), anyInt(), any())).thenReturn(fakePassword);
    }

    @Test
    public void testDataIsImportedCorrectly() throws GeneralSecurityException, SQLException, IOException {
        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE, getTestData());

        verify(mockPasswordDAO).create(eq(mockUser), eq(mockAdminGroup), eq(TEST_USERNAME), eq(TEST_PASSWORD),
                eq(TEST_LOCATION), eq(TEST_NOTES), eq(AuditingLevel.FULL), eq(true), anyLong(),
                eq(TEST_PARENT_NODE), any(), anyBoolean(), anyInt(), anyInt(), eq(Password.TYPE_SYSTEM), any());
    }

    @Test
    public void testCustomFieldsAreImported() throws GeneralSecurityException, SQLException, IOException {
        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE, getTestData("CF:cf1=cv1"));

        assertEquals("cv1", fakePassword.getCustomField("cf1"));
    }

    @Test
    public void testUserModifyPermissionsAreImported() throws GeneralSecurityException, SQLException, IOException {
        User user = mock(User.class);
        when(mockUserDAO.getByName(eq(TEST_LOGIN_ACCOUNT))).thenReturn(user);

        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE, getTestData("UM:" + TEST_LOGIN_ACCOUNT));

        verify(mockUserAccessControlDAO).create(user, fakePassword, PasswordPermission.MODIFY);
    }

    @Test
    public void testUserReadOnlyPermissionsAreImported() throws GeneralSecurityException, SQLException, IOException {
        User user = mock(User.class);
        when(mockUserDAO.getByName(eq(TEST_LOGIN_ACCOUNT))).thenReturn(user);

        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE, getTestData("UV:" + TEST_LOGIN_ACCOUNT));

        verify(mockUserAccessControlDAO).create(user, fakePassword, PasswordPermission.READ);
    }

    @Test
    public void testUserPermissionForNonExistentUserFails() throws SQLException {
        when(mockUserDAO.getByName(eq(TEST_LOGIN_ACCOUNT))).thenReturn(null);

        assertThrows(GeneralSecurityException.class, () -> instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE,
                getTestData("UV:" + TEST_LOGIN_ACCOUNT)));
    }

    @Test
    public void testDefaultUserPermissionIsSet() throws GeneralSecurityException, SQLException, IOException {
        when(mockUser.getId()).thenReturn(TEST_LOGIN_ACCOUNT_ID);
        when(mockUserDAO.getByIdDecrypted(eq(TEST_LOGIN_ACCOUNT_ID), any())).thenReturn(mockUser);

        GroupAccessControl accessControl = mock(GroupAccessControl.class);
        when(accessControl.getReadKey()).thenReturn(mockReadKey);
        when(mockGroupAccessControlDAO.get(eq(mockAdminGroup), eq(fakePassword)))
                .thenReturn(accessControl);

        FakeHierarchyNodePermissionDAO fakeHierarchyNodePermissionDAO =
                new FakeHierarchyNodePermissionDAO(Map.of(TEST_LOGIN_ACCOUNT_ID, PasswordPermission.READ), Map.of());

        instanceUnderTest = new PasswordImporter(mockPasswordDAO, mockUserDAO, mockGroupDAO, mockMembershipDAO,
                mockUserAccessControlDAO, mockGroupAccessControlDAO, fakeHierarchyNodePermissionDAO, mockAdminGroup);

        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE, getTestData());

        ArgumentCaptor<UserAccessControl> acCaptor = ArgumentCaptor.forClass(UserAccessControl.class);
        verify(mockUserAccessControlDAO).write(eq(mockUser), acCaptor.capture());
        UserAccessControl writtenAccessControl = acCaptor.getValue();
        assertEquals(mockReadKey, writtenAccessControl.getReadKey());
        assertNull(writtenAccessControl.getModifyKey());
    }

    @Test
    public void testDefaultUserPermissionIsOverridden() throws GeneralSecurityException, SQLException, IOException {
        when(mockUser.getId()).thenReturn(TEST_LOGIN_ACCOUNT_ID);
        when(mockUserDAO.getByIdDecrypted(eq(TEST_LOGIN_ACCOUNT_ID), any())).thenReturn(mockUser);
        when(mockUserDAO.getByName(eq(TEST_LOGIN_ACCOUNT))).thenReturn(mockUser);

        GroupAccessControl accessControl = mock(GroupAccessControl.class);
        when(mockGroupAccessControlDAO.get(eq(mockAdminGroup), eq(fakePassword)))
                .thenReturn(accessControl);

        UserAccessControl mockUserAccessControl = mock(UserAccessControl.class);
        when(mockUserAccessControlDAO.get(eq(mockUser), eq(fakePassword))).thenReturn(mockUserAccessControl);

        FakeHierarchyNodePermissionDAO fakeHierarchyNodePermissionDAO =
                new FakeHierarchyNodePermissionDAO(Map.of(TEST_LOGIN_ACCOUNT_ID, PasswordPermission.READ), Map.of());

        instanceUnderTest = new PasswordImporter(mockPasswordDAO, mockUserDAO, mockGroupDAO, mockMembershipDAO,
                mockUserAccessControlDAO, mockGroupAccessControlDAO, fakeHierarchyNodePermissionDAO, mockAdminGroup);

        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE,
                getTestData("UM:" + TEST_LOGIN_ACCOUNT));

        verify(mockUserAccessControlDAO).create(eq(mockUser), eq(fakePassword), eq(PasswordPermission.MODIFY));
        verify(mockUserAccessControlDAO, times(0)).write(any(User.class), any());
    }

    @Test
    public void testGroupModifyPermissionsAreImported() throws GeneralSecurityException, SQLException, IOException {
        Group group = mock(Group.class);
        when(mockGroupDAO.getByName(eq(TEST_USER_GROUP))).thenReturn(group);

        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE, getTestData("GM:" + TEST_USER_GROUP));

        verify(mockGroupAccessControlDAO).create(group, fakePassword, PasswordPermission.MODIFY);
    }

    @Test
    public void testGroupReadOnlyPermissionsAreImported() throws GeneralSecurityException, SQLException, IOException {
        Group group = mock(Group.class);
        when(mockGroupDAO.getByName(eq(TEST_USER_GROUP))).thenReturn(group);

        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE, getTestData("GV:" + TEST_USER_GROUP));

        verify(mockGroupAccessControlDAO).create(group, fakePassword, PasswordPermission.READ);
    }

    @Test
    public void testGroupPermissionForNonExistentUserFails() throws SQLException {
        when(mockGroupDAO.getByName(eq(TEST_USER_GROUP))).thenReturn(null);

        assertThrows(GeneralSecurityException.class, () -> instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE,
                getTestData("GV:" + TEST_USER_GROUP)));
    }

    @Test
    public void testGroupAndUserReadOnlyPermissionsAreImported() throws GeneralSecurityException, SQLException, IOException {
        Group group = mock(Group.class);
        when(mockGroupDAO.getByName(eq(TEST_USER_GROUP))).thenReturn(group);
        User user = mock(User.class);
        when(mockUserDAO.getByName(eq(TEST_LOGIN_ACCOUNT))).thenReturn(user);

        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE,
                getTestData("GV:" + TEST_USER_GROUP, "UV:" + TEST_LOGIN_ACCOUNT));

        verify(mockGroupAccessControlDAO).create(group, fakePassword, PasswordPermission.READ);
        verify(mockUserAccessControlDAO).create(user, fakePassword, PasswordPermission.READ);
    }

    @Test
    public void testCustomFieldGroupAndUserReadOnlyPermissionsAreImported()
            throws GeneralSecurityException, SQLException, IOException {
        Group group = mock(Group.class);
        when(mockGroupDAO.getByName(eq(TEST_USER_GROUP))).thenReturn(group);
        User user = mock(User.class);
        when(mockUserDAO.getByName(eq(TEST_LOGIN_ACCOUNT))).thenReturn(user);

        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE,
                getTestData("GV:" + TEST_USER_GROUP, "UV:" + TEST_LOGIN_ACCOUNT));

        verify(mockGroupAccessControlDAO).create(group, fakePassword, PasswordPermission.READ);
        verify(mockUserAccessControlDAO).create(user, fakePassword, PasswordPermission.READ);
    }

    @Test
    public void testDefaultGroupPermissionIsSet() throws GeneralSecurityException, SQLException, IOException {
        Group group = mock(Group.class);
        when(group.getId()).thenReturn(TEST_USER_GROUP_ID);
        when(mockGroupDAO.getByIdDecrypted(eq(TEST_USER_GROUP_ID), any())).thenReturn(group);
        GroupAccessControl accessControl = mock(GroupAccessControl.class);
        when(accessControl.getReadKey()).thenReturn(mockReadKey);
        when(mockGroupAccessControlDAO.get(eq(mockAdminGroup), eq(fakePassword)))
                .thenReturn(accessControl);
        ArgumentCaptor<GroupAccessControl> acCaptor = ArgumentCaptor.forClass(GroupAccessControl.class);

        FakeHierarchyNodePermissionDAO fakeHierarchyNodePermissionDAO =
                new FakeHierarchyNodePermissionDAO(Map.of(), Map.of(TEST_USER_GROUP_ID, PasswordPermission.READ));

        instanceUnderTest = new PasswordImporter(mockPasswordDAO, mockUserDAO, mockGroupDAO, mockMembershipDAO,
                mockUserAccessControlDAO, mockGroupAccessControlDAO, fakeHierarchyNodePermissionDAO, mockAdminGroup);

        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE, getTestData());

        verify(mockGroupAccessControlDAO).write(eq(group), acCaptor.capture());
        GroupAccessControl writtenAccessControl = acCaptor.getValue();
        assertEquals(mockReadKey, writtenAccessControl.getReadKey());
        assertNull(writtenAccessControl.getModifyKey());
    }

    @Test
    public void testDefaultGroupPermissionIsOverridden() throws GeneralSecurityException, SQLException, IOException {
        Group group = mock(Group.class);
        when(group.getId()).thenReturn(TEST_USER_GROUP_ID);
        when(mockGroupDAO.getByName(eq(TEST_USER_GROUP))).thenReturn(group);
        when(mockGroupDAO.getByIdDecrypted(eq(TEST_USER_GROUP_ID), any())).thenReturn(group);

        GroupAccessControl accessControl = mock(GroupAccessControl.class);
        when(mockGroupAccessControlDAO.get(any(Group.class), eq(fakePassword)))
                .thenReturn(accessControl);

        FakeHierarchyNodePermissionDAO fakeHierarchyNodePermissionDAO =
                new FakeHierarchyNodePermissionDAO(Map.of(), Map.of(TEST_USER_GROUP_ID, PasswordPermission.READ));

        instanceUnderTest = new PasswordImporter(mockPasswordDAO, mockUserDAO, mockGroupDAO, mockMembershipDAO,
                mockUserAccessControlDAO, mockGroupAccessControlDAO, fakeHierarchyNodePermissionDAO, mockAdminGroup);

        instanceUnderTest.importPassword(mockUser, TEST_PARENT_NODE, getTestData("GM:" + TEST_USER_GROUP));

        verify(mockGroupAccessControlDAO).create(group, fakePassword, PasswordPermission.MODIFY);
        verify(mockGroupAccessControlDAO, times(0)).write(any(), any());
    }

    private static class FakeHierarchyNodePermissionDAO extends HierarchyNodePermissionDAO {
        private final Map<String, PasswordPermission> userDefaults;
        private final Map<String, PasswordPermission> groupDefaults;

        FakeHierarchyNodePermissionDAO(Map<String, PasswordPermission> userDefaults,
                                       Map<String, PasswordPermission> groupDefaults) {
            this.userDefaults = userDefaults;
            this.groupDefaults = groupDefaults;
        }

        @Override
        public void getDefaultPermissionsForNode(String nodeId, Map<String, PasswordPermission> userPermMap,
                                                 Map<String, PasswordPermission> groupPermMap) {
            userPermMap.putAll(userDefaults);
            groupPermMap.putAll(groupDefaults);
        }

        @Override
        public void getDefaultPermissionsForNodeIncludingInherited(String nodeId,
                                                                   Map<String, PasswordPermission> userPermMap,
                                                                   Map<String, PasswordPermission> groupPermMap) {
            getDefaultPermissionsForNode(nodeId, userPermMap, groupPermMap);
        }
    }
}
