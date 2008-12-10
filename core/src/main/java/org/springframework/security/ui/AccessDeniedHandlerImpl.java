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

package org.springframework.security.ui;

import org.springframework.security.AccessDeniedException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Base implementation of {@link AccessDeniedHandler}.<p>This implementation sends a 403 (SC_FORBIDDEN) HTTP error
 * code. In addition, if a {@link #errorPage} is defined, the implementation will perform a request dispatcher
 * "forward" to the specified error page view. Being a "forward", the <code>SecurityContextHolder</code> will remain
 * populated. This is of benefit if the view (or a tag library or macro) wishes to access the
 * <code>SecurityContextHolder</code>. The request scope will also be populated with the exception itself, available
 * from the key {@link #SPRING_SECURITY_ACCESS_DENIED_EXCEPTION_KEY}.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    //~ Static fields/initializers =====================================================================================

    public static final String SPRING_SECURITY_ACCESS_DENIED_EXCEPTION_KEY = "SPRING_SECURITY_403_EXCEPTION";
    protected static final Log logger = LogFactory.getLog(AccessDeniedHandlerImpl.class);

    //~ Instance fields ================================================================================================

    private String errorPage;

    //~ Methods ========================================================================================================

    public void handle(ServletRequest request, ServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException, ServletException {
        if (!response.isCommitted()) {
            if (errorPage != null) {
                // Put exception into request scope (perhaps of use to a view)
                request.setAttribute(SPRING_SECURITY_ACCESS_DENIED_EXCEPTION_KEY, accessDeniedException);

                // Set the 403 status code.
                HttpServletResponse resp = (HttpServletResponse) response;
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);

                // forward to error page.
                RequestDispatcher dispatcher = request.getRequestDispatcher(errorPage);
                dispatcher.forward(request, response);
            } else {
                HttpServletResponse resp = (HttpServletResponse) response;
                resp.sendError(HttpServletResponse.SC_FORBIDDEN, accessDeniedException.getMessage());
            }
        }
    }

    /**
     * The error page to use. Must begin with a "/" and is interpreted relative to the current context root.
     *
     * @param errorPage the dispatcher path to display
     *
     * @throws IllegalArgumentException if the argument doesn't comply with the above limitations
     */
    public void setErrorPage(String errorPage) {
        if ((errorPage != null) && !errorPage.startsWith("/")) {
            throw new IllegalArgumentException("errorPage must begin with '/'");
        }

        this.errorPage = errorPage;
    }
}
