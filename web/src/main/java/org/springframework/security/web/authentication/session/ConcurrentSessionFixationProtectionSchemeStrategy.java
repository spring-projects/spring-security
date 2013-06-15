package org.springframework.security.web.authentication.session;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.util.Assert;

/**
 * Strategy which handles concurrent session-control, in addition to the functionality provided by the base class
 * ({@link SessionFixationProtectionSchemeStrategy}).
 *
 * When invoked following an authentication, it will check whether the user in question should be allowed to proceed,
 * by comparing the number of sessions they already have active with the configured {@code maximumSessions} value.
 * The {@link SessionRegistry} is used as the source of data on authenticated users and session data.
 * <p>
 * If a user has reached the maximum number of permitted sessions, the behaviour depends on the
 * {@code exceptionIfMaxExceeded} property. The default behaviour is to expired the least recently used session, which
 * will be invalidated by the {@link org.springframework.security.web.session.ConcurrentSessionFilter} if accessed
 * again. If {@code exceptionIfMaxExceeded} is set to {@code true}, however, the user will be prevented from starting
 * a new authenticated session.
 * <p>
 * This strategy can be injected into both the {@link org.springframework.security.web.session.SessionManagementFilter}
 * and instances of {@link org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter}
 * (typically {@link org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter}).
 *
 * @author Luke Taylor
 * @author Nicholas Williams
 * @since 3.2
 * @see SessionFixationProtectionSchemeStrategy
 * @see SessionFixationProtectionScheme
 */
public class ConcurrentSessionFixationProtectionSchemeStrategy extends SessionFixationProtectionSchemeStrategy
        implements MessageSourceAware {
    /**
     * The message source from which the exceeded limit message is retrieved.
     */
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    /**
     * The session registry which should be updated whenever changes are made to an authenticated session.
     */
    private final SessionRegistry sessionRegistry;

    /**
     * Whether an exception should be thrown if the maximum number of sessions is exceeded.
     */
    private boolean exceptionIfMaximumExceeded = false;

    /**
     * The maximum number of sessions a user is permitted to have simultaneously.
     */
    private int maximumSessions = 1;

    /**
     * Constructs a new strategy.
     *
     * @param sessionRegistry the session registry which should be updated when the authenticated session is changed.
     */
    public ConcurrentSessionFixationProtectionSchemeStrategy(SessionRegistry sessionRegistry) {
        Assert.notNull(sessionRegistry, "The sessionRegistry cannot be null");
        super.setAlwaysCreateSession(true);
        this.sessionRegistry = sessionRegistry;
    }

    /**
     * This method first checks whether the user has exceeded the maximum number of allowed sessions. It then calls
     * {@link SessionFixationProtectionSchemeStrategy#onAuthentication(Authentication, HttpServletRequest, HttpServletResponse)}
     * to apply session fixation protection, if configured. Finally, it updates the session registry with the details
     * of the session.
     */
    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request,
                                 HttpServletResponse response) {
        checkAuthenticationAllowed(authentication, request);

        // Allow the parent to create a new session if necessary
        super.onAuthentication(authentication, request, response);

        sessionRegistry.registerNewSession(request.getSession().getId(), authentication.getPrincipal());
    }

    /**
     * Checks whether the user has exceeded the maximum number of allowed sessions.
     */
    private void checkAuthenticationAllowed(Authentication authentication, HttpServletRequest request)
            throws AuthenticationException {

        final List<SessionInformation> sessions = sessionRegistry.getAllSessions(authentication.getPrincipal(), false);

        int sessionCount = sessions.size();
        int allowedSessions = getMaximumSessionsForThisUser(authentication);

        if (sessionCount < allowedSessions) {
            // They haven't got too many login sessions running at present
            return;
        }

        if (allowedSessions == -1) {
            // We permit unlimited logins
            return;
        }

        if (sessionCount == allowedSessions) {
            HttpSession session = request.getSession(false);

            if (session != null) {
                // Only permit it though if this request is associated with one of the already registered sessions
                for (SessionInformation si : sessions) {
                    if (si.getSessionId().equals(session.getId())) {
                        return;
                    }
                }
            }
            // If the session is null, a new one will be created by the parent class, exceeding the allowed number
        }

        allowableSessionsExceeded(sessions, allowedSessions);
    }

    /**
     * Method intended for use by subclasses to override the maximum number of sessions that are permitted for
     * a particular authentication. The default implementation simply returns the {@code maximumSessions} value
     * for the bean.
     *
     * @param authentication to determine the maximum sessions for
     * @return either -1 meaning unlimited, or a positive integer to limit (never zero)
     */
    @SuppressWarnings("unused")
    protected int getMaximumSessionsForThisUser(Authentication authentication) {
        return this.maximumSessions;
    }

    /**
     * Allows subclasses to customise behaviour when too many sessions are detected.
     *
     * @param sessions either {@code null} or all unexpired sessions associated with the principal
     * @param allowableSessions the number of concurrent sessions the user is allowed to have
     *
     */
    protected void allowableSessionsExceeded(List<SessionInformation> sessions, int allowableSessions)
            throws SessionAuthenticationException {
        if (this.exceptionIfMaximumExceeded || sessions == null) {
            throw new SessionAuthenticationException(
                    messages.getMessage("ConcurrentSessionControlStrategy.exceededAllowed",
                    new Object[] { allowableSessions },
                    "Maximum sessions of {0} for this principal exceeded.")
            );
        }

        // Determine least recently used session, and mark it for invalidation
        SessionInformation leastRecentlyUsed = null;

        for (SessionInformation session : sessions) {
            if (leastRecentlyUsed == null || session.getLastRequest().before(leastRecentlyUsed.getLastRequest())) {
                leastRecentlyUsed = session;
            }
        }

        assert leastRecentlyUsed != null;
        leastRecentlyUsed.expireNow();
    }

    /**
     * Sets the {@code exceptionIfMaximumExceeded} property, which determines whether the user should be prevented
     * from opening more sessions than allowed. If set to {@code true}, a {@code SessionAuthenticationException}
     * will be raised when a user exceeds the maximum number of sessions permitted. If set to {@code false}, the
     * user's least-recently-used session will be invalided when the user exceeds the maximum number of sessions
     * permitted.
     *
     * @param exceptionIfMaximumExceeded Whether an exception should be raised when the limit is exceeded. Defaults to
     *                                   {@code false}.
     */
    public void setExceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
        this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
    }

    /**
     * Sets the {@code maxSessions} property. The default value is 1. Use -1 for unlimited sessions.
     *
     * @param maximumSessions The maximum number of permitted sessions a user can have open simultaneously.
     */
    public void setMaximumSessions(int maximumSessions) {
        Assert.isTrue(maximumSessions != 0,
                "The maximum must either be a positive integer or -1 to specify unlimited sessions.");
        this.maximumSessions = maximumSessions;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    @Override
    public final void setAlwaysCreateSession(boolean alwaysCreateSession) {
        if (!alwaysCreateSession) {
            throw new IllegalArgumentException(
                    "Cannot set 'alwaysCreateSession' to false when concurrent session control is required"
            );
        }
    }
}
