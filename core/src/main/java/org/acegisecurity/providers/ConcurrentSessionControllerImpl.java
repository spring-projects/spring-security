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

package net.sf.acegisecurity.providers;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationTrustResolver;
import net.sf.acegisecurity.AuthenticationTrustResolverImpl;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.ui.WebAuthenticationDetails;
import net.sf.acegisecurity.ui.session.HttpSessionDestroyedEvent;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


/**
 * Used by the {@link ProviderManager} to track Authentications and their
 * respective sessions. A given user is allowed {@link #setMaxSessions(int)}
 * sessions. If they attempt to exceed that ammount a {@link
 * ConcurrentLoginException} will be thrown. The
 * ConcurrentSessionControllerImpl class will listen for {@link
 * HttpSessionDestroyedEvent}s in the ApplicationContext to remove a session
 * from the internal tracking. <b>This class will not function properly
 * without a {@link net.sf.acegisecurity.ui.session.HttpSessionEventPublisher}
 * configured in web.xml.</b>
 *
 * @author Ray Krueger
 * @author Ben Alex
 */
public class ConcurrentSessionControllerImpl
        implements ConcurrentSessionController, ApplicationListener {
    //~ Instance fields ========================================================

    protected Map principalsToSessions = new HashMap();
    protected Map sessionsToPrincipals = new HashMap();
    protected Set sessionSet = new HashSet();
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private int maxSessions = 1;

    //~ Methods ================================================================

    /**
     * Set the maximum number of sessions a user is allowed to have, defaults
     * to 1. Setting this to anything less than 1 will allow unlimited
     * sessions
     *
     * @param maxSessions
     */
    public void setMaxSessions(int maxSessions) {
        this.maxSessions = maxSessions;
    }

    /**
     * The maximum sessions per user.
     *
     * @return int
     */
    public int getMaxSessions() {
        return maxSessions;
    }

    /**
     * The trustResolver to use for determining Anonymous users and ignoring
     * them. Defaults to {@link AuthenticationTrustResolverImpl}
     *
     * @param trustResolver
     */
    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }

    /**
     * Get the configured AuthenticationTrustResolver
     *
     * @return The configured AuthenticationTrustResolver or {@link
     *         AuthenticationTrustResolverImpl} by default.
     */
    public AuthenticationTrustResolver getTrustResolver() {
        return trustResolver;
    }

    /**
     * Called by the {@link ProviderManager} after receiving a response from a
     * configured AuthenticationProvider.
     *
     * @param request  Used to retieve the {@link WebAuthenticationDetails}
     * @param response Used to store the sessionId for the current Principal
     * @see #determineSessionPrincipal(net.sf.acegisecurity.Authentication)
     */
    public void afterAuthentication(Authentication request,
                                    Authentication response) {
        enforceConcurrentLogins(response);

        if (request.getDetails() instanceof WebAuthenticationDetails) {
            String sessionId = ((WebAuthenticationDetails) request.getDetails())
                    .getSessionId();
            addSession(determineSessionPrincipal(response), sessionId);
        }
    }

    /**
     * Called by the {@link ProviderManager} before iterating the configured
     * {@link AuthenticationProvider}s
     *
     * @param request The Authentication in question
     * @throws ConcurrentLoginException if the user has already met the {@link
     *                                  #setMaxSessions(int)}
     */
    public void beforeAuthentication(Authentication request)
            throws ConcurrentLoginException {
        enforceConcurrentLogins(request);
    }

    /**
     * Checks for {@link HttpSessionDestroyedEvent}s and calls {@link
     * #removeSession(String)} for the destoyed HttpSessions id.
     *
     * @param event
     */
    public void onApplicationEvent(ApplicationEvent event) {
        if (event instanceof HttpSessionDestroyedEvent) {
            String sessionId = ((HttpSession) event.getSource()).getId();
            removeSession(sessionId);
        }
    }

    /**
     * Compares the sessionIds stored for the given principal to determine if
     * the given sessionId is new or existing.
     *
     * @param principal The principal in question
     * @param sessionId The new or existing sessionId
     * @return true if it's the same as a session already in use, false if it
     *         is a new session
     */
    protected boolean isActiveSession(Object principal, String sessionId) {
        Set sessions = (Set) principalsToSessions.get(principal);

        if (sessions == null) {
            return false;
        }

        return sessions.contains(sessionId);
    }

    /**
     * Updates internal maps with the sessionId for the given principal. Can be
     * overridden by subclasses to provide a specialized means of principal
     * -&gt; session tracking.
     *
     * @param principal
     * @param sessionId
     */
    protected void addSession(Object principal, String sessionId) {
        Set sessions = (Set) principalsToSessions.get(principal);

        if (sessions == null) {
            sessions = new HashSet();
            principalsToSessions.put(principal, sessions);
        }

        sessions.add(sessionId);
        sessionsToPrincipals.put(sessionId, principal);
    }

    /**
     * Counts the number of sessions in use by the given principal
     *
     * @param principal The principal object
     * @return 0 if there are no sessions, &gt; if there are any
     */
    protected int countSessions(Object principal) {
        Set set = (Set) principalsToSessions.get(principal);

        if (set == null) {
            return 0;
        }

        return set.size();
    }

    /**
     * Checks to see if the Authentication principal is of type UserDetails. If
     * it is then the {@link net.sf.acegisecurity.UserDetails#getUsername()}
     * is returned. Otherwise Authentication.getPrincipal().toString() is
     * returned. Subclasses can override this method to provide a more
     * specific implementation.
     *
     * @param auth The Authentication in question
     * @return The principal to be used as the key against sessions
     */
    protected Object determineSessionPrincipal(Authentication auth) {
        if (auth.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) auth.getPrincipal()).getUsername();
        } else {
            return auth.getPrincipal().toString();
        }
    }

    /**
     * Called by both the beforeAuthentication and afterAuthentication methods.
     * Anonymous requests as determined by the configured {@link
     * AuthenticationTrustResolver} are ignored. If the details are
     * WebAuthenticationDetails, get the sessionId and and the principal off
     * of the authentication using the {@link
     * #determineSessionPrincipal(net.sf.acegisecurity.Authentication)}
     * method.  Uses the sessionId and principal to determine if the session
     * is new, and if the user is already at the maxSessions value. Subclasses
     * may override for more specific functionality
     *
     * @param request Authentication being evaluated
     * @throws ConcurrentLoginException If the session is new, and the user is
     *                                  already at maxSessions
     */
    protected void enforceConcurrentLogins(Authentication request)
            throws ConcurrentLoginException {
        //If the max is less than 1, sessions are unlimited
        if (maxSessions < 1) {
            return;
        }

        //If it is an anonymous user, ignore them
        if (trustResolver.isAnonymous(request)) {
            return;
        }

        if (request.getDetails() instanceof WebAuthenticationDetails) {
            String sessionId = ((WebAuthenticationDetails) request.getDetails())
                    .getSessionId();

            Object principal = determineSessionPrincipal(request);

            if (!isActiveSession(principal, sessionId)) {
                if (maxSessions == countSessions(principal)) {
                    //The user is AT their max, toss them out
                    throw new ConcurrentLoginException(principal
                            + " has reached the maximum concurrent logins");
                }
            }
        }
    }

    /**
     * Remove the given sessionId from storage. Used by {@link
     * #onApplicationEvent(org.springframework.context.ApplicationEvent)} for
     * HttpSessionDestroyedEvent
     *
     * @param sessionId
     */
    protected void removeSession(String sessionId) {
        // find out which principal is associated with this sessionId
        Object associatedPrincipal = sessionsToPrincipals.get(sessionId);

        if (associatedPrincipal != null) {
            Set sessions = (Set) principalsToSessions.get(associatedPrincipal);
            sessions.remove(sessionId);

            if (sessions.isEmpty()) {
                principalsToSessions.remove(associatedPrincipal);
            }

            sessionsToPrincipals.remove(sessionId);
        }
    }
}
