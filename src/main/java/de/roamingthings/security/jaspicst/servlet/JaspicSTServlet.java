package de.roamingthings.security.jaspicst.servlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Logger;

/**
 */
public class JaspicSTServlet extends HttpServlet {
    private static final Logger log = Logger.getLogger(JaspicSTServlet.class.getName());

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        final String requestURI = req.getRequestURI();
        final String pathInfo = req.getPathInfo();
        if (pathInfo.equals("/logout")) {
            req.logout();
            resp.sendRedirect(req.getContextPath());
            return;
        }

        final PrintWriter writer = resp.getWriter();

        writer.println("<html><head><title>Servlet</title></head><body>");
        writer.println("<p>Servlet called with URI: " + requestURI + "</p>");
        writer.println("<p>Session ID is: " + req.getSession().getId() + "</p>");
        writer.println("<p>Principal is: " + req.getUserPrincipal() + "</p>");
        writer.println("<p>Link back to <a href=\"" + req.getContextPath() + "/index.xhtml\">index page</a></p>");
        writer.println("</body></html>");

        writer.close();
    }
}
