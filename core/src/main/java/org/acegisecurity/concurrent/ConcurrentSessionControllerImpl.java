/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.concurrent;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;


/**
 * Base implementation of {@link ConcurrentSessionControllerImpl} which
 * prohibits simultaneous logins.
 * 
 * <p>
 * By default uses {@link org.acegisecurity.concurrent.SessionRegistryImpl},
 * although any <code>SessionRegistry</code> may be used.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConcurrentSessionControllerImpl
    implements ConcurrentSessionController, InitializingBean {
    //~ Instance fields ========================================================

    private SessionRegistry sessionRegistry = new SessionRegistryImpl();
    private int maximumSessions = 1;
    private boolean exceptionIfMaximumExceeded = false;

    //~ Methods ================================================================

    public void setMaximumSessions(int maximumSessions) {
        this.maximumSessions = maximumSessions;
    }

    public void setSessionRegistry(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    public void setExceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
		this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
	}

	public void afterPropertiesSet() throws Exception {
        Assert.notNull(sessionRegistry, "SessionRegistry required");
        Assert.isTrue(maximumSessions != 0,
            "MaximumLogins must be either -1 to allow unlimited logins, or a positive integer to specify a maximum");
    }

    public void checkAuthenticationAllowed(Authentication request)
        throws AuthenticationException {
        Assert.notNull(request,
            "Authentication request cannot be null (violation of interface contract)");

        Object principal = SessionRegistryUtils
            .obtainPrincipalFromAuthentication(request);
        String sessionId = SessionRegistryUtils
            .obtainSessionIdFromAuthentication(request);

        SessionInformation[] sessions = sessionRegistry.getAllSessions(principal);

        int sessionCount = 0;

        if (sessions != null) {
            sessionCount = sessions.length;
        }

        int allowableSessions = getMaximumSessionsForThisUser(request);
        Assert.isTrue(allowableSessions != 0,
            "getMaximumSessionsForThisUser() must return either -1 to allow unlimited logins, or a positive integer to specify a maximum");

        if (sessionCount < allowableSessions) {
            return;
        } else if (sessionCount == allowableSessions) {
            // Only permit it though if this request is associated with one of the sessions
            for (int i = 0; i < sessionCount; i++) {
                if (sessions[i].getSessionId().equals(sessionId)) {
                    return;
                }
            }
        }

        allowableSessionsExceeded(sessionId, sessions, allowableSessions, sessionRegistry);
    }
    
    /**
     * Allows subclasses to customise behaviour when too many sessions are
     * detected.
     * 
     * @param sessionId the session ID of the present request
     * @param sessions either <code>null</code> or all unexpired sessions associated with the principal
     * @param registry an instance of the <code>SessionRegistry</code> for subclass use
     */
    protected void allowableSessionsExceeded(String sessionId, SessionInformation[] sessions, int allowableSessions, SessionRegistry registry) {
        if (exceptionIfMaximumExceeded || sessions == null) {
        	throw new ConcurrentLoginException("Maximum sessions of "
                    + allowableSessions + " for this principal exceeded");
        }
        
        // Determine least recently used session, and mark it for invalidation
        SessionInformation leastRecentlyUsed = null;
        for (int i = 0; i < sessions.length; i++) {
        	if (leastRecentlyUsed == null || sessions[i].getLastRequest().before(leastRecentlyUsed.getLastRequest())) {
        		leastRecentlyUsed = sessions[i];
        	}
        }
        
        leastRecentlyUsed.expireNow();
    }

    public void registerSuccessfulAuthentication(Authentication authentication) {
        Assert.notNull(authentication,
            "Authentication cannot be null (violation of interface contract)");

        Object principal = SessionRegistryUtils
            .obtainPrincipalFromAuthentication(authentication);
        String sessionId = SessionRegistryUtils
            .obtainSessionIdFromAuthentication(authentication);

        sessionRegistry.removeSessionInformation(sessionId);
        sessionRegistry.registerNewSession(sessionId, principal);
    }

    /**
     * Method intended for use by subclasses to override the maximum number of
     * sessions that are permitted for a particular authentication. The
     * default implementation simply returns the <code>maximumSessions</code>
     * value for the bean.
     *
     * @param authentication to determine the maximum sessions for
     *
     * @return either -1 meaning unlimited, or a positive integer to limit
     *         (never zero)
     */
    protected int getMaximumSessionsForThisUser(Authentication authentication) {
        return maximumSessions;
    }
}
