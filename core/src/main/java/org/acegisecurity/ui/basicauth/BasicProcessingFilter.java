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

package net.sf.acegisecurity.ui.basicauth;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.security.SecureContext;
import net.sf.acegisecurity.context.security.SecureContextUtils;
import net.sf.acegisecurity.intercept.web.AuthenticationEntryPoint;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.ui.WebAuthenticationDetails;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;

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
 * into the <code>ContextHolder</code>.
 * 
 * <P>
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
 * will be placed into the <code>ContextHolder</code>.
 * </p>
 * 
 * <p>
 * If authentication fails, an {@link AuthenticationEntryPoint} implementation
 * is called. Usually this should be {@link BasicProcessingFilterEntryPoint},
 * which will prompt the user to authenticate again via BASIC authentication.
 * </p>
 * 
 * <P>
 * Basic authentication is an attractive protocol because it is simple and
 * widely deployed. However, it still transmits a password in clear text and
 * as such is undesirable in many situations. Digest authentication is also
 * provided by Acegi Security and should be used instead of Basic
 * authentication wherever possible. See {@link
 * net.sf.acegisecurity.ui.digestauth.DigestProcessingFilter}.
 * </p>
 * 
 * <P>
 * <B>Do not use this class directly.</B> Instead configure
 * <code>web.xml</code> to use the {@link
 * net.sf.acegisecurity.util.FilterToBeanProxy}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicProcessingFilter implements Filter, InitializingBean {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(BasicProcessingFilter.class);

    //~ Instance fields ========================================================

    private AuthenticationEntryPoint authenticationEntryPoint;
    private AuthenticationManager authenticationManager;

    //~ Methods ================================================================

    public void setAuthenticationEntryPoint(
        AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    public AuthenticationEntryPoint getAuthenticationEntryPoint() {
        return authenticationEntryPoint;
    }

    public void setAuthenticationManager(
        AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void afterPropertiesSet() throws Exception {
        if (this.authenticationManager == null) {
            throw new IllegalArgumentException(
                "An AuthenticationManager is required");
        }

        if (this.authenticationEntryPoint == null) {
            throw new IllegalArgumentException(
                "An AuthenticationEntryPoint is required");
        }
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

            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username,
                    password);
            authRequest.setDetails(new WebAuthenticationDetails(httpRequest));

            Authentication authResult;
            SecureContext sc = SecureContextUtils.getSecureContext();

            try {
                authResult = authenticationManager.authenticate(authRequest);
            } catch (AuthenticationException failed) {
                // Authentication failed
                if (logger.isDebugEnabled()) {
                    logger.debug("Authentication request for user: " + username
                        + " failed: " + failed.toString());
                }

                sc.setAuthentication(null);
                ContextHolder.setContext(sc);
                authenticationEntryPoint.commence(request, response, failed);

                return;
            }

            // Authentication success
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication success: " + authResult.toString());
            }

            sc.setAuthentication(authResult);
            ContextHolder.setContext(sc);
        }

        chain.doFilter(request, response);
    }

    public void init(FilterConfig arg0) throws ServletException {}
}
