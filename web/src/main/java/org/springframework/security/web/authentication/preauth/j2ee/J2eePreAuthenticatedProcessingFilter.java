package org.springframework.security.web.authentication.preauth.j2ee;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * This AbstractPreAuthenticatedProcessingFilter implementation is based on the
 * J2EE container-based authentication mechanism. It will use the J2EE user
 * principal name as the pre-authenticated principal.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class J2eePreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

    /**
     * Return the J2EE user name.
     */
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
        Object principal = httpRequest.getUserPrincipal() == null ? null : httpRequest.getUserPrincipal().getName();
        if (logger.isDebugEnabled()) {
            logger.debug("PreAuthenticated J2EE principal: " + principal);
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
