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
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Detects that a user has been authenticated since the start of the request and, if they have, calls the
 * configured {@link SessionAuthenticationStrategy} to perform any session-related activity such as
 * activating session-fixation protection mechanisms or checking for multiple concurrent logins.
 *
 * @author Martin Algesten
 * @author Luke Taylor
 * @since 2.0
 */
public class SessionManagementFilter extends GenericFilterBean {
    //~ Static fields/initializers =====================================================================================

    static final String FILTER_APPLIED = "__spring_security_session_mgmt_filter_applied";

    //~ Instance fields ================================================================================================

    private final SecurityContextRepository securityContextRepository;
    private SessionAuthenticationStrategy sessionStrategy;
    private final AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();
    private String invalidSessionUrl;
    private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public SessionManagementFilter(SecurityContextRepository securityContextRepository) {
        this(securityContextRepository, new SessionFixationProtectionStrategy());
    }

    public SessionManagementFilter(SecurityContextRepository securityContextRepository, SessionAuthenticationStrategy sessionStrategy) {
        this.securityContextRepository = securityContextRepository;
        this.sessionStrategy = sessionStrategy;
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
                try {
                    sessionStrategy.onAuthentication(authentication, request, response);
                } catch (SessionAuthenticationException e) {
                    // The session strategy can reject the authentication
                    logger.debug("SessionAuthenticationStrategy rejected the authentication object", e);
                    SecurityContextHolder.clearContext();
                    failureHandler.onAuthenticationFailure(request, response, e);

                    return;
                }
                // Eagerly save the security context to make it available for any possible re-entrant
                // requests which may occur before the current request completes. SEC-1396.
                securityContextRepository.saveContext(SecurityContextHolder.getContext(), request, response);
            } else {
             // No security context or authentication present. Check for a session timeout
                if (request.getRequestedSessionId() != null && !request.isRequestedSessionIdValid()) {
                    logger.debug("Requested session ID" + request.getRequestedSessionId() + " is invalid.");

                    if (invalidSessionUrl != null) {
                        logger.debug("Starting new session (if required) and redirecting to '" + invalidSessionUrl + "'");
                        request.getSession();
                        redirectStrategy.sendRedirect(request, response, invalidSessionUrl);

                        return;
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
     * @param sessionStrategy the strategy object. If not set, a {@link SessionFixationProtectionStrategy} is used.
     * @deprecated Use constructor injection
     */
    @Deprecated
    public void setSessionAuthenticationStrategy(SessionAuthenticationStrategy sessionStrategy) {
        Assert.notNull(sessionStrategy, "authenticatedSessionStratedy must not be null");
        this.sessionStrategy = sessionStrategy;
    }

    /**
     * Sets the URL to which the response should be redirected if the user agent requests an invalid session Id.
     * If the property is not set, no action will be taken.
     *
     * @param invalidSessionUrl
     */
    public void setInvalidSessionUrl(String invalidSessionUrl) {
        this.invalidSessionUrl = invalidSessionUrl;
    }

    /**
     * The handler which will be invoked if the <tt>AuthenticatedSessionStrategy</tt> raises a
     * <tt>SessionAuthenticationException</tt>, indicating that the user is not allowed to be authenticated for this
     * session (typically because they already have too many sessions open).
     *
     */
    public void setAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
        Assert.notNull(failureHandler, "failureHandler cannot be null");
        this.failureHandler = failureHandler;
    }

    public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
        this.redirectStrategy  = redirectStrategy;
    }
}
