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

package org.springframework.security.concurrent;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.ui.FilterChainOrderUtils;
import org.springframework.security.ui.SpringSecurityFilter;
import org.springframework.util.Assert;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


/**
 * Filter required by concurrent session handling package.
 * <p>This filter performs two functions. First, it calls
 * {@link org.springframework.security.concurrent.SessionRegistry#refreshLastRequest(String)} for each request.
 * That way, registered sessions always have a correct "last update" date/time. Second, it retrieves
 * {@link org.springframework.security.concurrent.SessionInformation} from the <code>SessionRegistry</code>
 * for each request and checks if the session has been marked as expired.
 * If it has been marked as expired, the session is invalidated. The invalidation of the session will also cause the
 * request to redirect to the URL specified, and a
 * {@link org.springframework.security.ui.session.HttpSessionDestroyedEvent} to be published via the
 * {@link org.springframework.security.ui.session.HttpSessionEventPublisher} registered in <code>web.xml</code>.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConcurrentSessionFilter extends SpringSecurityFilter implements InitializingBean {
    //~ Instance fields ================================================================================================

    private SessionRegistry sessionRegistry;
    private String expiredUrl;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(sessionRegistry, "SessionRegistry required");
    }

    public void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpSession session = request.getSession(false);

        if (session != null) {
            SessionInformation info = sessionRegistry.getSessionInformation(session.getId());

            if (info != null) {
                if (info.isExpired()) {
                    // Expired - abort processing
                    session.invalidate();

                    if (expiredUrl != null) {
                        String targetUrl = request.getContextPath() + expiredUrl;
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

    public void setExpiredUrl(String expiredUrl) {
        this.expiredUrl = expiredUrl;
    }

    public void setSessionRegistry(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    public int getOrder() {
        return FilterChainOrderUtils.CONCURRENT_SESSION_FILTER_ORDER;
    }
}
