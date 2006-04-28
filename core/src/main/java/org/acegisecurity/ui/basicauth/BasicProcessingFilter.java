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

package org.acegisecurity.ui.basicauth;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;

import org.acegisecurity.context.SecurityContextHolder;

import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.acegisecurity.ui.AuthenticationDetailsSource;
import org.acegisecurity.ui.AuthenticationDetailsSourceImpl;
import org.acegisecurity.ui.AuthenticationEntryPoint;
import org.acegisecurity.ui.rememberme.RememberMeServices;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

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


/**
 * Processes a HTTP request's BASIC authorization headers, putting the result
 * into the <code>SecurityContextHolder</code>.
 * 
 * <p>
 * For a detailed background on what this filter is designed to process, refer
 * to <A HREF="http://www.faqs.org/rfcs/rfc1945.html">RFC 1945, Section
 * 11.1</A>. Any realm name presented in the HTTP request is ignored.
 * </p>
 * 
 * <p>
 * In summary, this filter is responsible for processing any request that has a
 * HTTP request header of <code>Authorization</code> with an authentication
 * scheme of <code>Basic</code> and a Base64-encoded
 * <code>username:password</code> token. For example, to authenticate user
 * "Aladdin" with password "open sesame" the following header would be
 * presented:
 * </p>
 * 
 * <p>
 * <code>Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==</code>.
 * </p>
 * 
 * <p>
 * This filter can be used to provide BASIC authentication services to both
 * remoting protocol clients (such as Hessian and SOAP) as well as standard
 * user agents (such as Internet Explorer and Netscape).
 * </p>
 * 
 * <P>
 * If authentication is successful, the resulting {@link Authentication} object
 * will be placed into the <code>SecurityContextHolder</code>.
 * </p>
 * 
 * <p>
 * If authentication fails and <code>ignoreFailure</code> is <code>false</code>
 * (the default), an {@link AuthenticationEntryPoint} implementation is
 * called. Usually this should be {@link BasicProcessingFilterEntryPoint},
 * which will prompt the user to authenticate again via BASIC authentication.
 * </p>
 * 
 * <p>
 * Basic authentication is an attractive protocol because it is simple and
 * widely deployed. However, it still transmits a password in clear text and
 * as such is undesirable in many situations. Digest authentication is also
 * provided by Acegi Security and should be used instead of Basic
 * authentication wherever possible. See {@link
 * org.acegisecurity.ui.digestauth.DigestProcessingFilter}.
 * </p>
 * 
 * <p>
 * Note that if a {@link #rememberMeServices} is set, this filter will
 * automatically send back remember-me details to the client. Therefore,
 * subsequent requests will not need to present a BASIC authentication header
 * as they will be authenticated using the remember-me mechanism.
 * </p>
 * 
 * <p>
 * <b>Do not use this class directly.</b> Instead configure
 * <code>web.xml</code> to use the {@link
 * org.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicProcessingFilter implements Filter, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(BasicProcessingFilter.class);

    //~ Instance fields ========================================================

    private AuthenticationDetailsSource authenticationDetailsSource = new AuthenticationDetailsSourceImpl();
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AuthenticationManager authenticationManager;
    private RememberMeServices rememberMeServices;
    private boolean ignoreFailure = false;

    //~ Methods ================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.notNull(this.authenticationManager,
            "An AuthenticationManager is required");
        Assert.notNull(this.authenticationEntryPoint,
            "An AuthenticationEntryPoint is required");
    }

    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest)) {
            throw new ServletException("Can only process HttpServletRequest");
        }

        if (!(response instanceof HttpServletResponse)) {
            throw new ServletException("Can only process HttpServletResponse");
        }

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String header = httpRequest.getHeader("Authorization");

        if (logger.isDebugEnabled()) {
            logger.debug("Authorization header: " + header);
        }

        if ((header != null) && header.startsWith("Basic ")) {
            String base64Token = header.substring(6);
            String token = new String(Base64.decodeBase64(
                        base64Token.getBytes()));

            String username = "";
            String password = "";
            int delim = token.indexOf(":");

            if (delim != -1) {
                username = token.substring(0, delim);
                password = token.substring(delim + 1);
            }

            // Only reauthenticate if username doesn't match SecurityContextHolder and user isn't authenticated (see SEC-53)
            Authentication existingAuth = SecurityContextHolder.getContext()
                                                               .getAuthentication();

            if ((existingAuth == null)
                || !existingAuth.getName().equals(username)
                || !existingAuth.isAuthenticated()) {
                UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username,
                        password);
                authRequest.setDetails(authenticationDetailsSource.buildDetails(
                        (HttpServletRequest) request));

                Authentication authResult;

                try {
                    authResult = authenticationManager.authenticate(authRequest);
                } catch (AuthenticationException failed) {
                    // Authentication failed
                    if (logger.isDebugEnabled()) {
                        logger.debug("Authentication request for user: "
                            + username + " failed: " + failed.toString());
                    }

                    SecurityContextHolder.getContext().setAuthentication(null);

                    if (rememberMeServices != null) {
                        rememberMeServices.loginFail(httpRequest, httpResponse);
                    }

                    if (ignoreFailure) {
                        chain.doFilter(request, response);
                    } else {
                        authenticationEntryPoint.commence(request, response,
                            failed);
                    }

                    return;
                }

                // Authentication success
                if (logger.isDebugEnabled()) {
                    logger.debug("Authentication success: "
                        + authResult.toString());
                }

                SecurityContextHolder.getContext().setAuthentication(authResult);

                if (rememberMeServices != null) {
                    rememberMeServices.loginSuccess(httpRequest, httpResponse,
                        authResult);
                }
            }
        }

        chain.doFilter(request, response);
    }

    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return authenticationEntryPoint;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void init(FilterConfig arg0) throws ServletException {}

    public boolean isIgnoreFailure() {
        return ignoreFailure;
    }

    public void setAuthenticationDetailsSource(
        AuthenticationDetailsSource authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource,
            "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setAuthenticationEntryPoint(
        AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    public void setAuthenticationManager(
        AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public void setIgnoreFailure(boolean ignoreFailure) {
        this.ignoreFailure = ignoreFailure;
    }

    public void setRememberMeServices(RememberMeServices rememberMeServices) {
        this.rememberMeServices = rememberMeServices;
    }
}
