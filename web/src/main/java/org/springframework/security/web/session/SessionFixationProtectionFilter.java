package org.springframework.security.web.session;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SpringSecurityFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;

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
public class SessionFixationProtectionFilter extends SpringSecurityFilter {
    //~ Static fields/initializers =====================================================================================

    static final String FILTER_APPLIED = "__spring_security_session_fixation_filter_applied";

    //~ Instance fields ================================================================================================

    private final SecurityContextRepository securityContextRepository;

    private AuthenticatedSessionStrategy sessionStrategy = new DefaultAuthenticatedSessionStrategy();

    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    public SessionFixationProtectionFilter(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }

    protected void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

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
}
