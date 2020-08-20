package com.enterprisepasswordsafe.engine.passwords;

import com.enterprisepasswordsafe.database.Group;
import com.enterprisepasswordsafe.database.GroupAccessControlDAO;
import com.enterprisepasswordsafe.database.HierarchyNodePermissionDAO;
import com.enterprisepasswordsafe.database.Password;
import com.enterprisepasswordsafe.database.PasswordDAO;
import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.database.UserDAO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class PasswordImporterTests {
    private static final String TEST_USERNAME = "username";
    private static final String TEST_LOCATION = "location";
    private static final String TEST_PASSWORD = "password";
    private static final String TEST_NOTES = "notes";
    private static final String TEST_PARENT_NODE = "0";

    @Mock
    User mockUser;
    @Mock
    Group mockAdminGroup;
    @Mock
    Password mockPassword;

    @Mock
    PasswordDAO mockPasswordDAO;
    @Mock
    UserDAO mockUserDAO;
    @Mock
    GroupAccessControlDAO mockGroupAccessControlDAO;
    @Mock
    HierarchyNodePermissionDAO hierarchyNodePermissionDAO;

    private PasswordImporter instanceUnderTest;

    private static List<String> getTestData() {
        return List.of(TEST_LOCATION, TEST_USERNAME, TEST_PASSWORD, TEST_NOTES, "F", "True");
    }

    @BeforeEach
    public void setUp() {
        instanceUnderTest = new PasswordImporter(mockPasswordDAO, mockUserDAO, mockGroupAccessControlDAO,
                hierarchyNodePermissionDAO);
    }

    @Test
    public void testDataIsImportedCorrectly() throws GeneralSecurityException, SQLException, IOException {
        when(mockPasswordDAO.create(any(), any(), any(), any(), any(), any(), any(), anyBoolean(), anyLong(), any(),
                any(), anyBoolean(), anyInt(), anyInt(), anyInt(), any())).thenReturn(mockPassword);

        instanceUnderTest.importPassword(mockUser, mockAdminGroup, TEST_PARENT_NODE, getTestData());

        verify(mockPasswordDAO).create(eq(mockUser), eq(mockAdminGroup), eq(TEST_USERNAME), eq(TEST_PASSWORD),
                eq(TEST_LOCATION), eq(TEST_NOTES), eq(AuditingLevel.FULL), eq(true), anyLong(),
                eq(TEST_PARENT_NODE), any(), anyBoolean(), anyInt(), anyInt(), eq(Password.TYPE_SYSTEM), any());
    }
}
