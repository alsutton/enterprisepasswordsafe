package com.enterprisepasswordsafe.ui.web.servlets;

import org.junit.jupiter.api.BeforeEach;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ServletTestBase {
    HttpServletRequest mockRequest;
    HttpServletResponse mockResponse;
    RequestDispatcher mockRequestDispatcher;

    @BeforeEach
    public void setUp() {
        mockRequest = mock(HttpServletRequest.class);
        mockResponse = mock(HttpServletResponse.class);
        mockRequestDispatcher = mock(RequestDispatcher.class);
        when(mockRequest.getRequestDispatcher(any())).thenReturn(mockRequestDispatcher);
    }
}
