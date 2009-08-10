package org.springframework.security.web.session;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Detects that a user has been authenticated since the start of the request and, if they have, calls the
 * configured {@link AuthenticatedSessionStrategy} to perform any session-related activity (such as
 * activating session-fixation protection mechanisms).
 * <p>
 * This is essentially a generalization of the functionality that was implemented for SEC-399.
 *
 * @author Martin Algesten
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class SessionManagementFilter extends GenericFilterBean {
    //~ Static fields/initializers =====================================================================================

    static final String FILTER_APPLIED = "__spring_security_session_fixation_filter_applied";

    //~ Instance fields ================================================================================================

    private final SecurityContextRepository securityContextRepository;

    private AuthenticatedSessionStrategy sessionStrategy = new DefaultAuthenticatedSessionStrategy();

    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    private String invalidSessionUrl;

    public SessionManagementFilter(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }

    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (request.getAttribute(FILTER_APPLIED) != null) {
            chain.doFilter(request, response);
            return;
        }

        request.setAttribute(FILTER_APPLIED, Boolean.TRUE);

        if (!securityContextRepository.containsContext(request)) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null && !authenticationTrustResolver.isAnonymous(authentication)) {
             // The user has been authenticated during the current request, so call the session strategy
                sessionStrategy.onAuthenticationSuccess(authentication, request, response);
            } else {
             // No security context or authentication present. Check for a session timeout
                if (request.getRequestedSessionId() != null && !request.isRequestedSessionIdValid()) {
                    if (invalidSessionUrl != null) {
                        response.sendRedirect(invalidSessionUrl);
                    }
                }
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Sets the strategy object which handles the session management behaviour when a
     * user has been authenticated during the current request.
     *
     * @param sessionStrategy the strategy object. If not set, a {@link DefaultAuthenticatedSessionStrategy} is used.
     */
    public void setAuthenticatedSessionStrategy(AuthenticatedSessionStrategy sessionStrategy) {
        Assert.notNull(sessionStrategy, "authenticatedSessionStratedy must not be null");
        this.sessionStrategy = sessionStrategy;
    }

    /**
     * Sets the URL to which the response should be redirected if the user agent request and invalid session Id.
     * If the property is not set, no action will be taken.
     *
     * @param invalidSessionUrl
     */
    public void setInvalidSessionUrl(String invalidSessionUrl) {
        this.invalidSessionUrl = invalidSessionUrl;
    }
}
