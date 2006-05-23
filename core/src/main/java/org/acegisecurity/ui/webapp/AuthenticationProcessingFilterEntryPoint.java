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

package org.acegisecurity.ui.webapp;

import org.acegisecurity.AuthenticationException;

import org.acegisecurity.ui.AuthenticationEntryPoint;

import org.acegisecurity.util.PortMapper;
import org.acegisecurity.util.PortMapperImpl;
import org.acegisecurity.util.PortResolver;
import org.acegisecurity.util.PortResolverImpl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * <p>Used by the <code>SecurityEnforcementFilter</code> to commence authentication via the {@link
 * AuthenticationProcessingFilter}. This object holds the location of the login form, relative to the web app context
 * path, and is used to commence a redirect to that form.</p>
 *  <p>By setting the <em>forceHttps</em> property to true, you may configure the class to force the protocol used
 * for the login form to be <code>HTTPS</code>, even if the original intercepted request for a resource used the
 * <code>HTTP</code> protocol. When this happens, after a successful login (via HTTPS), the original resource will
 * still be accessed as HTTP, via the original request URL. For the forced HTTPS feature to work, the {@link
 * PortMapper} is consulted to determine the HTTP:HTTPS pairs.</p>
 *
 * @author Ben Alex
 * @author colin sampaleanu
 * @author Omri Spector
 * @version $Id$
 */
public class AuthenticationProcessingFilterEntryPoint implements AuthenticationEntryPoint, InitializingBean {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(AuthenticationProcessingFilterEntryPoint.class);

    //~ Instance fields ================================================================================================

    private PortMapper portMapper = new PortMapperImpl();
    private PortResolver portResolver = new PortResolverImpl();
    private String loginFormUrl;
    private boolean forceHttps = false;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(loginFormUrl, "loginFormUrl must be specified");
        Assert.notNull(portMapper, "portMapper must be specified");
        Assert.notNull(portResolver, "portResolver must be specified");
    }

    public void commence(ServletRequest request, ServletResponse response, AuthenticationException authException)
        throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        String scheme = request.getScheme();
        String serverName = request.getServerName();
        int serverPort = portResolver.getServerPort(request);
        String contextPath = req.getContextPath();

        boolean inHttp = "http".equals(scheme.toLowerCase());
        boolean inHttps = "https".equals(scheme.toLowerCase());

        boolean includePort = true;

        if (inHttp && (serverPort == 80)) {
            includePort = false;
        } else if (inHttps && (serverPort == 443)) {
            includePort = false;
        }

        String redirectUrl = scheme + "://" + serverName + ((includePort) ? (":" + serverPort) : "") + contextPath
            + loginFormUrl;

        if (forceHttps && inHttp) {
            Integer httpsPort = (Integer) portMapper.lookupHttpsPort(new Integer(serverPort));

            if (httpsPort != null) {
                if (httpsPort.intValue() == 443) {
                    includePort = false;
                } else {
                    includePort = true;
                }

                redirectUrl = "https://" + serverName + ((includePort) ? (":" + httpsPort) : "") + contextPath
                    + loginFormUrl;
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Redirecting to: " + redirectUrl);
        }

        ((HttpServletResponse) response).sendRedirect(((HttpServletResponse) response).encodeRedirectURL(redirectUrl));
    }

    public boolean getForceHttps() {
        return forceHttps;
    }

    public String getLoginFormUrl() {
        return loginFormUrl;
    }

    public PortMapper getPortMapper() {
        return portMapper;
    }

    public PortResolver getPortResolver() {
        return portResolver;
    }

    /**
     * Set to true to force login form access to be via https. If this value is ture (the default is false),
     * and the incoming request for the protected resource which triggered the interceptor was not already
     * <code>https</code>, then
     *
     * @param forceHttps
     */
    public void setForceHttps(boolean forceHttps) {
        this.forceHttps = forceHttps;
    }

    /**
     * The URL where the <code>AuthenticationProcessingFilter</code> login page can be found. Should be
     * relative to the web-app context path, and include a leading <code>/</code>
     *
     * @param loginFormUrl
     */
    public void setLoginFormUrl(String loginFormUrl) {
        this.loginFormUrl = loginFormUrl;
    }

    public void setPortMapper(PortMapper portMapper) {
        this.portMapper = portMapper;
    }

    public void setPortResolver(PortResolver portResolver) {
        this.portResolver = portResolver;
    }
}
