package org.springframework.security.web.authentication.preauth.websphere;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.util.Assert;

/**
 * This method interceptor can be used in front of arbitrary Spring beans to make a Spring SecurityContext
 * available to the bean, based on the current WebSphere credentials.
 *
 * @author Ruud Senden
 * @since 1.0
 */
@Deprecated
public class WebSphere2SpringSecurityPropagationInterceptor implements MethodInterceptor {
    private static final Log logger = LogFactory.getLog(WebSphere2SpringSecurityPropagationInterceptor.class);
    private AuthenticationManager authenticationManager = null;
    private AuthenticationDetailsSource<?,?> authenticationDetailsSource = new WebSpherePreAuthenticatedAuthenticationDetailsSource();
    private final WASUsernameAndGroupsExtractor wasHelper;

    public WebSphere2SpringSecurityPropagationInterceptor() {
        this(new DefaultWASUsernameAndGroupsExtractor());
    }

    WebSphere2SpringSecurityPropagationInterceptor(WASUsernameAndGroupsExtractor wasHelper) {
        this.wasHelper = wasHelper;
    }

    /**
     * Authenticate with Spring Security based on WebSphere credentials before proceeding with method
     * invocation, and clean up the Spring Security Context after method invocation finishes.
     * @see org.aopalliance.intercept.MethodInterceptor#invoke(org.aopalliance.intercept.MethodInvocation)
     */
    public Object invoke(MethodInvocation methodInvocation) throws Throwable {
        try {
            logger.debug("Performing Spring Security authentication with WebSphere credentials");
            authenticateSpringSecurityWithWASCredentials();
            logger.debug("Proceeding with method invocation");
            return methodInvocation.proceed();
        } finally {
            logger.debug("Clearing Spring Security security context");
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * Retrieve the current WebSphere credentials and authenticate them with Spring Security
     * using the pre-authenticated authentication provider.
     */
    private void authenticateSpringSecurityWithWASCredentials() {
        Assert.notNull(authenticationManager);
        Assert.notNull(authenticationDetailsSource);

        String userName = wasHelper.getCurrentUserName();
        if (logger.isDebugEnabled()) { logger.debug("Creating authentication request for user "+userName); }
        PreAuthenticatedAuthenticationToken authRequest = new PreAuthenticatedAuthenticationToken(userName, "N/A");
        authRequest.setDetails(authenticationDetailsSource.buildDetails(null));
        if (logger.isDebugEnabled()) { logger.debug("Authentication request for user "+userName+": "+authRequest); }
        Authentication authResponse = authenticationManager.authenticate(authRequest);
        if (logger.isDebugEnabled()) { logger.debug("Authentication response for user "+userName+": "+authResponse); }
        SecurityContextHolder.getContext().setAuthentication(authResponse);
    }

    /**
     * @param authenticationManager The authenticationManager to set.
     */
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * @param authenticationDetailsSource The authenticationDetailsSource to set.
     */
    public void setAuthenticationDetailsSource(AuthenticationDetailsSource authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }
}
