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

package org.springframework.security.web.authentication.concurrent;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.concurrent.SessionInformation;
import org.springframework.security.authentication.concurrent.SessionRegistry;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SpringSecurityFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;


/**
 * Filter required by concurrent session handling package.
 * <p>
 * This filter performs two functions. First, it calls
 * {@link org.springframework.security.authentication.concurrent.SessionRegistry#refreshLastRequest(String)} for each request
 * so that registered sessions always have a correct "last update" date/time. Second, it retrieves a
 * {@link org.springframework.security.authentication.concurrent.SessionInformation} from the <code>SessionRegistry</code>
 * for each request and checks if the session has been marked as expired.
 * If it has been marked as expired, the configured logout handlers will be called (as happens with
 * {@link org.springframework.security.web.authentication.logout.LogoutFilter}), typically to invalidate the session.
 * A redirect to the expiredURL specified will be performed, and the session invalidation will cause an
 * {@link org.springframework.security.web.session.HttpSessionDestroyedEvent} to be published via the
 * {@link org.springframework.security.web.session.HttpSessionEventPublisher} registered in <code>web.xml</code>.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConcurrentSessionFilter extends SpringSecurityFilter implements InitializingBean {
    //~ Instance fields ================================================================================================

    private SessionRegistry sessionRegistry;
    private String expiredUrl;
    private LogoutHandler[] handlers = new LogoutHandler[] {new SecurityContextLogoutHandler()};

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(sessionRegistry, "SessionRegistry required");
        Assert.isTrue(expiredUrl == null || UrlUtils.isValidRedirectUrl(expiredUrl),
                expiredUrl + " isn't a valid redirect URL");
    }

    public void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpSession session = request.getSession(false);

        if (session != null) {
            SessionInformation info = sessionRegistry.getSessionInformation(session.getId());

            if (info != null) {
                if (info.isExpired()) {
                    // Expired - abort processing
                    doLogout(request, response);

                    String targetUrl = determineExpiredUrl(request, info);

                    if (targetUrl != null) {
                        targetUrl = request.getContextPath() + targetUrl;
                        response.sendRedirect(response.encodeRedirectURL(targetUrl));
                    } else {
                        response.getWriter().print("This session has been expired (possibly due to multiple concurrent " +
                                "logins being attempted as the same user).");
                        response.flushBuffer();
                    }

                    return;
                } else {
                    // Non-expired - update last request date/time
                    info.refreshLastRequest();
                }
            }
        }

        chain.doFilter(request, response);
    }

    protected String determineExpiredUrl(HttpServletRequest request, SessionInformation info) {
        return expiredUrl;
    }

    private void doLogout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        for (int i = 0; i < handlers.length; i++) {
            handlers[i].logout(request, response, auth);
        }
    }

    public void setExpiredUrl(String expiredUrl) {
        this.expiredUrl = expiredUrl;
    }

    public void setSessionRegistry(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    public void setLogoutHandlers(LogoutHandler[] handlers) {
        Assert.notNull(handlers);
        this.handlers = handlers;
    }
}
