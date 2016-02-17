package de.roamingthings.security.jaspic.common;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import java.util.Map;

/**
 * This class functions as a kind of factory for {@link ServerAuthContext} instances, which are delegates for the actual
 * {@link ServerAuthModule} (SAM) that we're after.
 *
 * This class is taken from the <a href="https://github.com/javaee-samples/javaee7-samples/tree/master/jaspic">jaspic samples</a>
 */
public class SimpleServerAuthConfig implements ServerAuthConfig {

    private String layer;
    private String appContext;
    private CallbackHandler handler;
    private Map<String, String> providerProperties;
    private ServerAuthModule serverAuthModule;

    public SimpleServerAuthConfig(String layer, String appContext, CallbackHandler handler,
                                Map<String, String> providerProperties, ServerAuthModule serverAuthModule) {
        this.layer = layer;
        this.appContext = appContext;
        this.handler = handler;
        this.providerProperties = providerProperties;
        this.serverAuthModule = serverAuthModule;
    }

    @Override
    public ServerAuthContext getAuthContext(String authContextID, Subject serviceSubject,
                                            @SuppressWarnings("rawtypes") Map properties) throws AuthException {
        return new SimpleServerAuthContext(handler, serverAuthModule);
    }

    // ### The methods below mostly just return what has been passed into the
    // constructor.
    // ### In practice they don't seem to be called

    @Override
    public String getMessageLayer() {
        return layer;
    }

    /**
     * It's not entirely clear what the difference is between the "application context identifier" (appContext) and the
     * "authentication context identifier" (authContext). In early iterations of the specification, authContext was called
     * "operation" and instead of the MessageInfo it was obtained by something called an "authParam".
     */
    @Override
    public String getAuthContextID(MessageInfo messageInfo) {
        return appContext;
    }

    @Override
    public String getAppContext() {
        return appContext;
    }

    @Override
    public void refresh() {
    }

    @Override
    public boolean isProtected() {
        return false;
    }

    public Map<String, String> getProviderProperties() {
        return providerProperties;
    }

}