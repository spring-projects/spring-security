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

package net.sf.acegisecurity.ui.basicauth;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.ui.webapp.HttpSessionIntegrationFilter;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import org.springframework.web.context.support.WebApplicationContextUtils;

import java.io.IOException;

import java.util.Map;

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
 * into the <code>HttpSession</code>.
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
 * Requests containing BASIC authentication headers are generally created by
 * remoting protocol libraries.  This filter is intended to process requests
 * made by such libraries.
 * </p>
 * 
 * <P>
 * If authentication is successful, the resulting {@link Authentication} object
 * will be placed into the <code>HttpSession</code> with the attribute defined
 * by {@link HttpSessionIntegrationFilter#ACEGI_SECURITY_AUTHENTICATION_KEY}.
 * </p>
 * 
 * <p>
 * If authentication fails, a <code>HttpServletResponse.SC_FORBIDDEN</code>
 * (403 error) response is sent. This is consistent with RFC 1945, Section 11,
 * which states, "<I>If the server does not wish to accept the credentials
 * sent with a request, it should return a 403 (forbidden) response.</I>".
 * </p>
 * 
 * <p>
 * This filter works with an {@link AuthenticationManager} which is used to
 * process each authentication request. By default, at init time, the filter
 * will use Spring's {@link
 * WebApplicationContextUtils#getWebApplicationContext(ServletContext sc)}
 * method to obtain an ApplicationContext instance, inside which must be a
 * configured AuthenticationManager instance. In the case where it is
 * desirable for  this filter to instantiate its own ApplicationContext
 * instance from which to obtain the AuthenticationManager, the location of
 * the config for this context may be specified with the optional
 * <code>contextConfigLocation</code> init param.
 * </p>
 * 
 * <p>
 * To use this filter, it is necessary to specify the following filter
 * initialization parameters:
 * </p>
 * 
 * <ul>
 * <li>
 * <code>contextConfigLocation</code> (optional, normally not used), indicates
 * the path to an application context that contains an {@link
 * AuthenticationManager} which should be used to process each authentication
 * request. If not specified, {@link
 * WebApplicationContextUtils#getWebApplicationContext(ServletContext sc)}
 * will be used to obtain the context.
 * </li>
 * </ul>
 * 
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicProcessingFilter implements Filter {
    //~ Static fields/initializers =============================================

    /**
     * Name of (optional) servlet filter parameter that can specify the config
     * location for a new ApplicationContext used to config this filter.
     */
    public static final String CONFIG_LOCATION_PARAM = "contextConfigLocation";
    private static final Log logger = LogFactory.getLog(BasicProcessingFilter.class);

    //~ Instance fields ========================================================

    private ApplicationContext ctx;
    private AuthenticationManager authenticationManager;
    private boolean ourContext = false;

    //~ Methods ================================================================

    public void destroy() {
        if (ourContext && ctx instanceof ConfigurableApplicationContext) {
            ((ConfigurableApplicationContext) ctx).close();
        }
    }

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

            UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username,
                    password);

            Authentication authResult;

            try {
                authResult = authenticationManager.authenticate(authRequest);
            } catch (AuthenticationException failed) {
                // Authentication failed
                if (logger.isDebugEnabled()) {
                    logger.debug("Authentication request for user: " + username
                        + " failed: " + failed.toString());
                }

                ((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN); // 403

                return;
            }

            // Authentication success
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication success: " + authResult.toString());
            }

            httpRequest.getSession().setAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY,
                authResult);
        }

        chain.doFilter(request, response);
    }

    public void init(FilterConfig filterConfig) throws ServletException {
        String appContextLocation = filterConfig.getInitParameter(CONFIG_LOCATION_PARAM);

        if ((appContextLocation != null) && (appContextLocation.length() > 0)) {
            ourContext = true;

            if (Thread.currentThread().getContextClassLoader().getResource(appContextLocation) == null) {
                throw new ServletException("Cannot locate "
                    + appContextLocation);
            }
        }

        try {
            if (!ourContext) {
                ctx = WebApplicationContextUtils
                    .getRequiredWebApplicationContext(filterConfig
                        .getServletContext());
            } else {
                ctx = new ClassPathXmlApplicationContext(appContextLocation);
            }
        } catch (RuntimeException e) {
            throw new ServletException(
                "Error obtaining/creating ApplicationContext for config. Must be stored in ServletContext, or optionally '"
                + CONFIG_LOCATION_PARAM
                + "' param may be used to allow creation of new context by this filter. See root error for additional details",
                e);
        }

        Map beans = ctx.getBeansOfType(AuthenticationManager.class, true, true);

        if (beans.size() == 0) {
            throw new ServletException(
                "Bean context must contain at least one bean of type AuthenticationManager");
        }

        String beanName = (String) beans.keySet().iterator().next();
        authenticationManager = (AuthenticationManager) beans.get(beanName);
    }
}
