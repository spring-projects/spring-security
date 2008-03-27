package org.springframework.security.ui.preauth.websphere;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.ui.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * This AbstractPreAuthenticatedProcessingFilter implementation is based on
 * WebSphere authentication. It will use the WebSphere RunAs user principal name 
 * as the pre-authenticated principal.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class WebSpherePreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {
    /**
     * Return the WebSphere user name.
     */
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
        Object principal = WASSecurityHelper.getCurrentUserName();
        if (logger.isDebugEnabled()) {
            logger.debug("PreAuthenticated WebSphere principal: " + principal);
        }
        return principal;
    }

    /**
     * For J2EE container-based authentication there is no generic way to
     * retrieve the credentials, as such this method returns a fixed dummy
     * value.
     */
    protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
        return "N/A";
    }

    public int getOrder() {
        return 0;
    }
}
