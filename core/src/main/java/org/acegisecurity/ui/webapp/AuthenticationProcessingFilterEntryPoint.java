/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.ui.webapp;

import net.sf.acegisecurity.intercept.web.AuthenticationEntryPoint;

import org.springframework.beans.factory.InitializingBean;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Used by the <code>SecurityEnforcementFilter</code> to commence
 * authentication via the {@link AuthenticationProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationProcessingFilterEntryPoint
    implements AuthenticationEntryPoint, InitializingBean {
    //~ Instance fields ========================================================

    /**
     * The URL where the <code>AuthenticationProcessingFilter</code> login page
     * can be found.
     */
    private String loginFormUrl;

    //~ Methods ================================================================

    public void setLoginFormUrl(String loginFormUrl) {
        this.loginFormUrl = loginFormUrl;
    }

    public String getLoginFormUrl() {
        return loginFormUrl;
    }

    public void afterPropertiesSet() throws Exception {
        if ((loginFormUrl == null) || "".equals(loginFormUrl)) {
            throw new IllegalArgumentException("loginFormUrl must be specified");
        }
    }

    public void commence(ServletRequest request, ServletResponse response)
        throws IOException, ServletException {
        ((HttpServletResponse) response).sendRedirect(((HttpServletRequest) request)
            .getContextPath() + loginFormUrl);
    }
}
