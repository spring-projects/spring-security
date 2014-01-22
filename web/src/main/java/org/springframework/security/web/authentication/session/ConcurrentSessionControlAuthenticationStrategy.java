package org.springframework.security.web.authentication.session;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;

/**
 * Strategy which handles concurrent session-control.
 *
 * <p>
 * When invoked following an authentication, it will check whether the user in
 * question should be allowed to proceed, by comparing the number of sessions
 * they already have active with the configured <tt>maximumSessions</tt> value.
 * The {@link SessionRegistry} is used as the source of data on authenticated
 * users and session data.
 * </p>
 * <p>
 * If a user has reached the maximum number of permitted sessions, the behaviour
 * depends on the <tt>exceptionIfMaxExceeded</tt> property. The default
 * behaviour is to expired the least recently used session, which will be
 * invalidated by the {@link ConcurrentSessionFilter} if accessed again. If
 * <tt>exceptionIfMaxExceeded</tt> is set to <tt>true</tt>, however, the user
 * will be prevented from starting a new authenticated session.
 * </p>
 * <p>
 * This strategy can be injected into both the {@link SessionManagementFilter}
 * and instances of {@link AbstractAuthenticationProcessingFilter} (typically
 * {@link UsernamePasswordAuthenticationFilter}), but is typically combined with
 * {@link RegisterSessionAuthenticationStrategy} using
 * {@link CompositeSessionAuthenticationStrategy}.
 * </p>
 *
 * @see CompositeSessionAuthenticationStrategy
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.2
 */
public class ConcurrentSessionControlAuthenticationStrategy implements MessageSourceAware, SessionAuthenticationStrategy {
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private final SessionRegistry sessionRegistry;
    private boolean exceptionIfMaximumExceeded = false;
    private int maximumSessions = 1;

    /**
     * @param sessionRegistry the session registry which should be updated when the authenticated session is changed.
     */
    public ConcurrentSessionControlAuthenticationStrategy(SessionRegistry sessionRegistry) {
        Assert.notNull(sessionRegistry, "The sessionRegistry cannot be null");
        this.sessionRegistry = sessionRegistry;
    }

    /**
     * In addition to the steps from the superclass, the sessionRegistry will be updated with the new session information.
     */
    public void onAuthentication(Authentication authentication, HttpServletRequest request,
            HttpServletResponse response) {

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

        allowableSessionsExceeded(sessions, allowedSessions, sessionRegistry);
    }

    /**
     * Method intended for use by subclasses to override the maximum number of sessions that are permitted for
     * a particular authentication. The default implementation simply returns the <code>maximumSessions</code> value
     * for the bean.
     *
     * @param authentication to determine the maximum sessions for
     *
     * @return either -1 meaning unlimited, or a positive integer to limit (never zero)
     */
    protected int getMaximumSessionsForThisUser(Authentication authentication) {
        return maximumSessions;
    }

    /**
     * Allows subclasses to customise behaviour when too many sessions are detected.
     *
     * @param sessions either <code>null</code> or all unexpired sessions associated with the principal
     * @param allowableSessions the number of concurrent sessions the user is allowed to have
     * @param registry an instance of the <code>SessionRegistry</code> for subclass use
     *
     */
    protected void allowableSessionsExceeded(List<SessionInformation> sessions, int allowableSessions,
            SessionRegistry registry) throws SessionAuthenticationException {
        if (exceptionIfMaximumExceeded || (sessions == null)) {
            throw new SessionAuthenticationException(messages.getMessage("ConcurrentSessionControlAuthenticationStrategy.exceededAllowed",
                    new Object[] {Integer.valueOf(allowableSessions)},
                    "Maximum sessions of {0} for this principal exceeded"));
        }

        // Determine least recently used session, and mark it for invalidation
        SessionInformation leastRecentlyUsed = null;

        for (SessionInformation session : sessions) {
            if ((leastRecentlyUsed == null)
                    || session.getLastRequest().before(leastRecentlyUsed.getLastRequest())) {
                leastRecentlyUsed = session;
            }
        }

        leastRecentlyUsed.expireNow();
    }

    /**
     * Sets the <tt>exceptionIfMaximumExceeded</tt> property, which determines
     * whether the user should be prevented from opening more sessions than
     * allowed. If set to <tt>true</tt>, a
     * <tt>SessionAuthenticationException</tt> will be raised which means the
     * user authenticating will be prevented from authenticating. if set to
     * <tt>false</tt>, the user that has already authenticated will be forcibly
     * logged out.
     *
     * @param exceptionIfMaximumExceeded
     *            defaults to <tt>false</tt>.
     */
    public void setExceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
        this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
    }

    /**
     * Sets the <tt>maxSessions</tt> property. The default value is 1. Use -1 for unlimited sessions.
     *
     * @param maximumSessions the maximimum number of permitted sessions a user can have open simultaneously.
     */
    public void setMaximumSessions(int maximumSessions) {
        Assert.isTrue(maximumSessions != 0,
            "MaximumLogins must be either -1 to allow unlimited logins, or a positive integer to specify a maximum");
        this.maximumSessions = maximumSessions;
    }

    /**
     * Sets the {@link MessageSource} used for reporting errors back to the user
     * when the user has exceeded the maximum number of authentications.
     */
    public void setMessageSource(MessageSource messageSource) {
        Assert.notNull(messageSource, "messageSource cannot be null");
        this.messages = new MessageSourceAccessor(messageSource);
    }
}
