package com.enterprisepasswordsafe.ui.web.servlets;

import com.enterprisepasswordsafe.engine.Repositories;
import com.enterprisepasswordsafe.engine.configuration.JDBCConfigurationRepository;
import com.enterprisepasswordsafe.engine.configuration.TestConfigurationJDBCConfigurationRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

public class VerifyJDBCConfigurationTest extends ServletTestBase {
    @AfterEach
    public void tearDown() {
        Repositories.reset();
    }

    @Test
    public void testExceptionDuringCheckedDetailsMaintainsConfiguration() throws ServletException, IOException {
        JDBCConfigurationRepository testConfigRepository = new TestConfigurationJDBCConfigurationRepository();
        Repositories.jdbcConfigurationRepository = testConfigRepository;

        VerifyJDBCConfiguration testInstance = new VerifyJDBCConfiguration();
        testInstance.doGet(mockRequest, mockResponse);

        verify(mockRequest).setAttribute(eq(VerifyJDBCConfiguration.JDBC_CONFIG_PROPERTY),
                eq(TestConfigurationJDBCConfigurationRepository.TEST_CONNECTION_INFORMATION));
    }
}
