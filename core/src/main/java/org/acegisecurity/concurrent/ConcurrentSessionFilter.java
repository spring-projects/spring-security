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

package net.sf.acegisecurity.concurrent;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;


/**
 * Filter required by concurrent session handling package.
 * 
 * <p>
 * This filter performs two functions. First, it calls {@link
 * net.sf.acegisecurity.concurrent.SessionRegistry#refreshLastRequest(String)}
 * for each request. That way, registered sessions always have a correct "last
 * update" date/time. Second, it retrieves {@link
 * net.sf.acegisecurity.concurrent.SessionInformation} from the
 * <code>SessionRegistry</code> for each request and checks if the session has
 * been marked as expired. If it has been marked as expired, the session is
 * invalidated. The invalidation of the session will also cause the request to
 * redirect to the URL specified, and a {@link
 * net.sf.acegisecurity.ui.session.HttpSessionDestroyedEvent} to be published
 * via the {@link net.sf.acegisecurity.ui.session.HttpSessionEventPublisher}
 * registered in <code>web.xml</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConcurrentSessionFilter implements Filter,
    InitializingBean {
    //~ Instance fields ========================================================

    private SessionRegistry sessionRegistry;
    private String expiredUrl;

    //~ Methods ================================================================

    public void setExpiredUrl(String expiredUrl) {
        this.expiredUrl = expiredUrl;
    }

    public void setSessionRegistry(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(sessionRegistry, "SessionRegistry required");
        Assert.hasText(expiredUrl, "ExpiredUrl required");
    }

    /**
     * Does nothing. We use IoC container lifecycle services instead.
     */
    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        Assert.isInstanceOf(HttpServletRequest.class, request,
            "Can only process HttpServletRequest");
        Assert.isInstanceOf(HttpServletResponse.class, response,
            "Can only process HttpServletResponse");

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        HttpSession session = httpRequest.getSession(false);

        if (session != null) {
            SessionInformation info = sessionRegistry.getSessionInformation(session
                    .getId());

            if (info != null) {
                if (info.isExpired()) {
                    // Expired - abort processing
                    session.invalidate();

                    String targetUrl = httpRequest.getContextPath()
                        + expiredUrl;
                    httpResponse.sendRedirect(httpResponse.encodeRedirectURL(
                            targetUrl));

                    return;
                } else {
                    // Non-expired - update last request date/time
                    info.refreshLastRequest();
                }
            }
        }

        chain.doFilter(request, response);
    }

    /**
     * Does nothing. We use IoC container lifecycle services instead.
     *
     * @param arg0 ignored
     *
     * @throws ServletException ignored
     */
    public void init(FilterConfig arg0) throws ServletException {}
}
