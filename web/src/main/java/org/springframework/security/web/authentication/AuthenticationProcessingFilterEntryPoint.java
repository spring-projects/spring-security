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

package org.springframework.security.web.authentication;

import org.springframework.security.AuthenticationException;


import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.ExceptionTranslationFilter;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.security.web.util.UrlUtils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Used by the {@link ExceptionTranslationFilter} to commence a form login
 * authentication via the {@link AuthenticationProcessingFilter}. This object
 * holds the location of the login form, relative to the web app context path,
 * and is used to commence a redirect to that form.
 * <p>
 * By setting the <em>forceHttps</em> property to true, you may configure the
 * class to force the protocol used for the login form to be <code>HTTPS</code>,
 * even if the original intercepted request for a resource used the
 * <code>HTTP</code> protocol. When this happens, after a successful login
 * (via HTTPS), the original resource will still be accessed as HTTP, via the
 * original request URL. For the forced HTTPS feature to work, the {@link
 * PortMapper} is consulted to determine the HTTP:HTTPS pairs.
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

    private boolean useForward = false;

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.isTrue(StringUtils.hasText(loginFormUrl) && UrlUtils.isValidRedirectUrl(loginFormUrl),
                "loginFormUrl must be specified and must be a valid redirect URL");
        Assert.notNull(portMapper, "portMapper must be specified");
        Assert.notNull(portResolver, "portResolver must be specified");
    }

    /**
     * Allows subclasses to modify the login form URL that should be applicable for a given request.
     *
     * @param request   the request
     * @param response  the response
     * @param exception the exception
     * @return the URL (cannot be null or empty; defaults to {@link #getLoginFormUrl()})
     */
    protected String determineUrlToUseForThisRequest(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) {

        return getLoginFormUrl();
    }

    /**
     * Performs the redirect (or forward) to the login form URL.
     */
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String redirectUrl = null;

        if (useForward) {

            if (forceHttps && "http".equals(request.getScheme())) {
                redirectUrl = buildHttpsRedirectUrlForRequest(httpRequest);
            }

            if (redirectUrl == null) {
                String loginForm = determineUrlToUseForThisRequest(httpRequest, httpResponse, authException);

                if (logger.isDebugEnabled()) {
                    logger.debug("Server side forward to: " + loginForm);
                }

                RequestDispatcher dispatcher = httpRequest.getRequestDispatcher(loginForm);

                dispatcher.forward(request, response);

                return;
            }
        } else {
            // redirect to login page. Use https if forceHttps true

            redirectUrl = buildRedirectUrlToLoginPage(httpRequest, httpResponse, authException);

        }

        httpResponse.sendRedirect(httpResponse.encodeRedirectURL(redirectUrl));
    }

    protected String buildRedirectUrlToLoginPage(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) {

        String loginForm = determineUrlToUseForThisRequest(request, response, authException);
        int serverPort = portResolver.getServerPort(request);
        String scheme = request.getScheme();

        RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();

        urlBuilder.setScheme(scheme);
        urlBuilder.setServerName(request.getServerName());
        urlBuilder.setPort(serverPort);
        urlBuilder.setContextPath(request.getContextPath());
        urlBuilder.setPathInfo(loginForm);

        if (forceHttps && "http".equals(scheme)) {
            Integer httpsPort = portMapper.lookupHttpsPort(new Integer(serverPort));

            if (httpsPort != null) {
                // Overwrite scheme and port in the redirect URL
                urlBuilder.setScheme("https");
                urlBuilder.setPort(httpsPort.intValue());
            } else {
                logger.warn("Unable to redirect to HTTPS as no port mapping found for HTTP port " + serverPort);
            }
        }

        return urlBuilder.getUrl();
    }

    /**
     * Builds a URL to redirect the supplied request to HTTPS.
     */
    protected String buildHttpsRedirectUrlForRequest(HttpServletRequest request)
            throws IOException, ServletException {

        int serverPort = portResolver.getServerPort(request);
        Integer httpsPort = portMapper.lookupHttpsPort(new Integer(serverPort));

        if (httpsPort != null) {
            RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
            urlBuilder.setScheme("https");
            urlBuilder.setServerName(request.getServerName());
            urlBuilder.setPort(httpsPort.intValue());
            urlBuilder.setContextPath(request.getContextPath());
            urlBuilder.setServletPath(request.getServletPath());
            urlBuilder.setPathInfo(request.getPathInfo());
            urlBuilder.setQuery(request.getQueryString());

            return urlBuilder.getUrl();
        }

        // Fall through to server-side forward with warning message
        logger.warn("Unable to redirect to HTTPS as no port mapping found for HTTP port " + serverPort);

        return null;
    }

    /**
     * Set to true to force login form access to be via https. If this value is true (the default is false),
     * and the incoming request for the protected resource which triggered the interceptor was not already
     * <code>https</code>, then the client will first be redirected to an https URL, even if <tt>serverSideRedirect</tt>
     * is set to <tt>true</tt>.
     */
    public void setForceHttps(boolean forceHttps) {
        this.forceHttps = forceHttps;
    }

    protected boolean isForceHttps() {
        return forceHttps;
    }

    /**
     * The URL where the <code>AuthenticationProcessingFilter</code> login
     * page can be found. Should be relative to the web-app context path, and
     * include a leading <code>/</code>
     */
    public void setLoginFormUrl(String loginFormUrl) {
        this.loginFormUrl = loginFormUrl;
    }

    public String getLoginFormUrl() {
        return loginFormUrl;
    }

    public void setPortMapper(PortMapper portMapper) {
        this.portMapper = portMapper;
    }

    protected PortMapper getPortMapper() {
        return portMapper;
    }

    public void setPortResolver(PortResolver portResolver) {
        this.portResolver = portResolver;
    }

    protected PortResolver getPortResolver() {
        return portResolver;
    }

    /**
     * Tells if we are to do a forward to the <code>loginFormUrl</code> using the <tt>RequestDispatcher</tt>,
     * instead of a 302 redirect.
     *
     * @param useForward
     */
    public void setUseForward(boolean useForward) {
        this.useForward = useForward;
    }

    protected boolean isUseForward() {
        return useForward;
    }
}
