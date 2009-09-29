package org.springframework.security.web.session;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.concurrent.SessionInformation;
import org.springframework.security.authentication.concurrent.SessionRegistry;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class ConcurrentSessionControlAuthenticatedSessionStrategy extends DefaultSessionAuthenticationStrategy
        implements MessageSourceAware {
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private final SessionRegistry sessionRegistry;
    private boolean exceptionIfMaximumExceeded = false;
    private int maximumSessions = 1;

    /**
     * @param sessionRegistry the session registry which should be updated when the authenticated session is changed.
     */
    public ConcurrentSessionControlAuthenticatedSessionStrategy(SessionRegistry sessionRegistry) {
        Assert.notNull(sessionRegistry, "The sessionRegistry cannot be null");
        super.setAlwaysCreateSession(true);
        this.sessionRegistry = sessionRegistry;
    }

    @Override
    public void onAuthentication(Authentication authentication, HttpServletRequest request,
            HttpServletResponse response) {
        checkAuthenticationAllowed(authentication, request);

        // Allow the parent to create a new session if necessary
        super.onAuthentication(authentication, request, response);
        sessionRegistry.registerNewSession(request.getSession().getId(), authentication.getPrincipal());
    }

    private void checkAuthenticationAllowed(Authentication authentication, HttpServletRequest request)
            throws AuthenticationException {

        final List<SessionInformation> sessions = sessionRegistry.getAllSessions(authentication.getPrincipal(), false);

        int sessionCount = sessions == null ? 0 : sessions.size();
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
     * @param sessionId the session ID of the present request
     * @param sessions either <code>null</code> or all unexpired sessions associated with the principal
     * @param allowableSessions the number of concurrent sessions the user is allowed to have
     * @param registry an instance of the <code>SessionRegistry</code> for subclass use
     *
     */
    protected void allowableSessionsExceeded(List<SessionInformation> sessions, int allowableSessions,
            SessionRegistry registry) {
        if (exceptionIfMaximumExceeded || (sessions == null)) {
            throw new SessionAuthenticationException(messages.getMessage("ConcurrentSessionControllerImpl.exceededAllowed",
                    new Object[] {new Integer(allowableSessions)},
                    "Maximum sessions of {0} for this principal exceeded"));
        }

        // Determine least recently used session, and mark it for invalidation
        SessionInformation leastRecentlyUsed = null;

        for (int i = 0; i < sessions.size(); i++) {
            if ((leastRecentlyUsed == null)
                    || sessions.get(i).getLastRequest().before(leastRecentlyUsed.getLastRequest())) {
                leastRecentlyUsed = sessions.get(i);
            }
        }

        leastRecentlyUsed.expireNow();
    }

    @Override
    protected void onSessionChange(String originalSessionId, HttpSession newSession, Authentication auth) {
        // Update the session registry
        sessionRegistry.removeSessionInformation(originalSessionId);
        sessionRegistry.registerNewSession(newSession.getId(), auth.getPrincipal());
    }

    public void setExceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
        this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
    }

    public void setMaximumSessions(int maximumSessions) {
        Assert.isTrue(maximumSessions != 0,
            "MaximumLogins must be either -1 to allow unlimited logins, or a positive integer to specify a maximum");
        this.maximumSessions = maximumSessions;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    @Override
    public final void setAlwaysCreateSession(boolean alwaysCreateSession) {
        if (!alwaysCreateSession) {
            throw new IllegalArgumentException("Cannot set alwaysCreateSession to false when concurrent session " +
                    "control is required");
        }
    }
}
