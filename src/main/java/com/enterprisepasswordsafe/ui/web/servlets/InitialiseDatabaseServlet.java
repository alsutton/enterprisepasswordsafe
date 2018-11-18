package com.enterprisepasswordsafe.ui.web.servlets;

import com.enterprisepasswordsafe.engine.Repositories;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePool;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.logging.Level;
import java.util.logging.Logger;

@WebServlet(name = "InitialiseDatabase", urlPatterns = {"/InitialiseDatabase"})
public class InitialiseDatabaseServlet extends HttpServlet {
    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException {
        Logger.getLogger(getClass().toString()).log(Level.WARNING,"Initialising Database");
        try {
            DatabasePool pool = Repositories.databasePoolFactory.getInstance();
            pool.initialiseDatabase();
            response.sendRedirect("/");
        } catch (Exception e) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "Error setting JDBC configuration", e);
            throw new ServletException("An error occurred whilst configuring your database.", e);
        }
    }
}
