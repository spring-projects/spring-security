/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication.concurrent;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;

import org.springframework.util.Assert;


/**
 * Base implementation of {@link ConcurrentSessionControllerImpl} which prohibits simultaneous logins.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConcurrentSessionControllerImpl implements ConcurrentSessionController, InitializingBean,
        MessageSourceAware {
    //~ Instance fields ================================================================================================

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private SessionRegistry sessionRegistry;
    private boolean exceptionIfMaximumExceeded = false;
    private int maximumSessions = 1;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(sessionRegistry, "SessionRegistry required");
        Assert.isTrue(maximumSessions != 0,
            "MaximumLogins must be either -1 to allow unlimited logins, or a positive integer to specify a maximum");
        Assert.notNull(this.messages, "A message source must be set");
    }

    /**
     * Allows subclasses to customise behaviour when too many sessions are detected.
     *
     * @param sessionId the session ID of the present request
     * @param sessions either <code>null</code> or all unexpired sessions associated with the principal
     * @param allowableSessions DOCUMENT ME!
     * @param registry an instance of the <code>SessionRegistry</code> for subclass use
     *
     * @throws ConcurrentLoginException if the
     */
    protected void allowableSessionsExceeded(String sessionId, List<SessionInformation> sessions, int allowableSessions,
            SessionRegistry registry) {
        if (exceptionIfMaximumExceeded || (sessions == null)) {
            throw new ConcurrentLoginException(messages.getMessage("ConcurrentSessionControllerImpl.exceededAllowed",
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

    public void checkAuthenticationAllowed(Authentication request) throws AuthenticationException {
        Assert.notNull(request, "Authentication request cannot be null (violation of interface contract)");

        String sessionId = obtainSessionId(request);

        final List<SessionInformation> sessions = sessionRegistry.getAllSessions(request.getPrincipal(), false);

        int sessionCount = sessions == null ? 0 : sessions.size();

        int allowableSessions = getMaximumSessionsForThisUser(request);
        Assert.isTrue(allowableSessions != 0, "getMaximumSessionsForThisUser() must return either -1 to allow "
                + "unlimited logins, or a positive integer to specify a maximum");

        if (sessionCount < allowableSessions) {
            // They haven't got too many login sessions running at present
            return;
        }

        if (allowableSessions == -1) {
            // We permit unlimited logins
            return;
        }

        if (sessionCount == allowableSessions) {
            // Only permit it though if this request is associated with one of the sessions
            for (SessionInformation si : sessions) {
                if (si.getSessionId().equals(sessionId)) {
                    return;
                }
            }
        }

        allowableSessionsExceeded(sessionId, sessions, allowableSessions, sessionRegistry);
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

    public void registerSuccessfulAuthentication(Authentication authentication) {
        Assert.notNull(authentication, "Authentication cannot be null (violation of interface contract)");

        sessionRegistry.registerNewSession(obtainSessionId(authentication), authentication.getPrincipal());
    }

    public void setExceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
        this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
    }

    public void setMaximumSessions(int maximumSessions) {
        this.maximumSessions = maximumSessions;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    public void setSessionRegistry(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    public SessionRegistry getSessionRegistry() {
        return sessionRegistry;
    }

    private String obtainSessionId(Authentication auth) {
        if (auth.getDetails() == null || !(auth.getDetails() instanceof SessionIdentifierAware)) {
            throw new IllegalArgumentException("The 'details' property of the supplied Authentication " +
                    "object must be set and must implement 'SessionIdentifierAware', but Authentication.getDetails() " +
                    "returned " + auth.getDetails());
        }

        String sessionId = ((SessionIdentifierAware) auth.getDetails()).getSessionId();
        Assert.hasText(sessionId, "SessionIdentifierAware did not return a Session ID (" + auth.getDetails() + ")");

        return sessionId;
    }
}
