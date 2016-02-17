package de.roamingthings.security.jaspic.simple.sam;


import de.roamingthings.security.jaspic.common.SimpleAuthConfigProvider;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;
import java.util.logging.Logger;

/**
 */
@WebListener
public class SamAutoRegistrationListener implements ServletContextListener {
    private static final Logger log = Logger.getLogger(SamAutoRegistrationListener.class.getName());

    public static void registerSAM(ServletContext context, ServerAuthModule serverAuthModule) {
        AuthConfigFactory.getFactory().registerConfigProvider(new SimpleAuthConfigProvider(serverAuthModule), "HttpServlet",
                getAppContextID(context), "Test authentication config provider");
    }

    public static String getAppContextID(ServletContext context) {
        return context.getVirtualServerName() + " " + context.getContextPath();
    }

    @Override
    public void contextInitialized(ServletContextEvent sce) {
        log.info("Initialize `RegisterServerAuthModule`");

        registerSAM(sce.getServletContext(), new RegisterServerAuthModule());
    }

    @Override
    public void contextDestroyed(ServletContextEvent arg0) {
    }
}