package de.roamingthings.security.jaspicst.servlet;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.logging.Logger;

/**
 */
//@WebFilter(filterName = "loginRedirectFilter", urlPatterns = "/*")
public class LoginRedirectFilter implements Filter {
    private static final Logger log = Logger.getLogger(LoginRedirectFilter.class.getName());

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;

        final String requestURI = httpServletRequest.getRequestURI();

        final Principal preChainUserPrincipal = httpServletRequest.getUserPrincipal();

        log.info("Pre-Chain user principal: " + preChainUserPrincipal);
        final String preSessionId = httpServletRequest.getSession().getId();
        log.info("Post session id: " + preSessionId);

        chain.doFilter(request, response);

        final String postSessionId = httpServletRequest.getSession().getId();
        final Boolean authSuccessRequest = (Boolean) httpServletRequest.getAttribute("authSuccessRequest");
        final Principal postChainUserPrincipal = httpServletRequest.getUserPrincipal();
        log.info("Post session id: " + postSessionId);
        log.info("AuthSuccessRequest: " + authSuccessRequest);
        log.info("Post-Chain user principal: " + postChainUserPrincipal);
    }

    @Override
    public void destroy() {

    }
}