package org.springframework.security.ui.preauth.j2ee;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.ui.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * This AbstractPreAuthenticatedProcessingFilter implementation is based on the
 * J2EE container-based authentication mechanism. It will use the J2EE user
 * principal name as the pre-authenticated principal.
 */
public class J2eePreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {
	private static final Log LOG = LogFactory.getLog(J2eePreAuthenticatedProcessingFilter.class);

	/**
	 * Return the J2EE user name.
	 */
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
		Object principal = httpRequest.getUserPrincipal() == null ? null : httpRequest.getUserPrincipal().getName();
		if (LOG.isDebugEnabled()) {
			LOG.debug("PreAuthenticated J2EE principal: " + principal);
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
