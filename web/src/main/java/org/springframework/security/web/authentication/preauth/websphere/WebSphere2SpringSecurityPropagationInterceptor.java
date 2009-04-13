package org.springframework.security.web.authentication.preauth.websphere;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * This method interceptor can be used in front of arbitrary Spring beans to make a Spring SecurityContext
 * available to the bean, based on the current WebSphere credentials.
 * 
 * @author Ruud Senden
 * @since 1.0
 */
public class WebSphere2SpringSecurityPropagationInterceptor implements MethodInterceptor {
    private static final Log LOG = LogFactory.getLog(WebSphere2SpringSecurityPropagationInterceptor.class);
    private AuthenticationManager authenticationManager = null;
    private AuthenticationDetailsSource authenticationDetailsSource = new WebSpherePreAuthenticatedAuthenticationDetailsSource();
    
    /**
     * Authenticate with Spring Security based on WebSphere credentials before proceeding with method
     * invocation, and clean up the Spring Security Context after method invocation finishes.
     * @see org.aopalliance.intercept.MethodInterceptor#invoke(org.aopalliance.intercept.MethodInvocation)
     */
    public Object invoke(MethodInvocation methodInvocation) throws Throwable {
        try {
            LOG.debug("Performing Spring Security authentication with WebSphere credentials");
            authenticateSpringSecurityWithWASCredentials(this);
            LOG.debug("Proceeding with method invocation");
            return methodInvocation.proceed();
        } finally {
            LOG.debug("Clearing Spring Security security context");
            clearSpringSecurityContext();
        }
    }
    
    /**
     * Retrieve the current WebSphere credentials and authenticate them with Spring Security
     * using the pre-authenticated authentication provider.
     * @param aContext The context to use for building the authentication details.
     */
    private final void authenticateSpringSecurityWithWASCredentials(Object aContext)
    {
        Assert.notNull(authenticationManager);
        Assert.notNull(authenticationDetailsSource);
        
        String userName = WASSecurityHelper.getCurrentUserName();
        if (LOG.isDebugEnabled()) { LOG.debug("Creating authentication request for user "+userName); }
        PreAuthenticatedAuthenticationToken authRequest = new PreAuthenticatedAuthenticationToken(userName,null);
        authRequest.setDetails(authenticationDetailsSource.buildDetails(null));
        if (LOG.isDebugEnabled()) { LOG.debug("Authentication request for user "+userName+": "+authRequest); }
        Authentication authResponse = authenticationManager.authenticate(authRequest);
        if (LOG.isDebugEnabled()) { LOG.debug("Authentication response for user "+userName+": "+authResponse); }
        SecurityContextHolder.getContext().setAuthentication(authResponse);
    }
    
    /**
     * Clear the Spring Security Context
     */
    private final void clearSpringSecurityContext()
    {
        SecurityContextHolder.clearContext();
    }

    /**
     * @return Returns the authenticationManager.
     */
    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }
    
    /**
     * @param authenticationManager The authenticationManager to set.
     */
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
    /**
     * @return Returns the authenticationDetailsSource.
     */
    public AuthenticationDetailsSource getAuthenticationDetailsSource() {
        return authenticationDetailsSource;
    }
    /**
     * @param authenticationDetailsSource The authenticationDetailsSource to set.
     */
    public void setAuthenticationDetailsSource(AuthenticationDetailsSource authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }
}
