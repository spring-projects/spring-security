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

package net.sf.acegisecurity.context;

import net.sf.acegisecurity.Authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


/**
 * <p>
 * Populates the <code>SecurityContext</code> with information obtained from
 * the <code>HttpSession</code>.
 * </p>
 * 
 * <p>
 * The <code>HttpSession</code> will be queried to retrieve the
 * <code>Authentication</code> that should be stored against the
 * <code>SecurityContext</code> for the duration of the web request. At the
 * end of the web request, any updates made to the
 * <code>SecurityContext</code> will be persisted back to the
 * <code>HttpSession</code> by this filter.
 * </p>
 * 
 * <p>
 * No <code>HttpSession</code> will be created by this filter if one does not
 * already exist. If at the end of the web request the
 * <code>HttpSession</code> does not exist, a <code>HttpSession</code> will
 * <b>only</b> be created if the current contents of
 * <code>SecurityContext</code> are not <code>null</code>. This avoids
 * needless <code>HttpSession</code> creation, but automates the storage of
 * changes made to the <code>SecurityContext</code>.
 * </p>
 * 
 * <P>
 * This filter will only execute once per request, to resolve servlet container
 * (specifically Weblogic) incompatibilities.
 * </p>
 * 
 * <p>
 * If for whatever reason no <code>HttpSession</code> should <b>ever</b> be
 * created (eg this filter is only being used with Basic authentication or
 * similar clients that will never present the same <code>jsessionid</code>
 * etc), the  {@link #setAllowSessionCreation(boolean)} should be set to
 * <code>false</code>. Only do this if you really need to conserve server
 * memory and ensure all classes using the <code>SecurityContext</code> are
 * designed to have no persistence of the <code>Authentication</code> between
 * web requests.
 * </p>
 * 
 * <p>
 * This filter MUST appear BEFORE any other Acegi Security related filters,
 * because this filter WILL REMOVE any <code>Authentication</code> it finds in
 * the <code>SecurityContext</code>.
 * </p>
 *
 * @author Ben Alex
 * @author Patrick Burleson
 * @version $Id$
 */
public class HttpSessionContextIntegrationFilter implements Filter {
    //~ Static fields/initializers =============================================

    protected static final Log logger = LogFactory.getLog(HttpSessionContextIntegrationFilter.class);
    private static final String FILTER_APPLIED = "__acegi_session_integration_filter_applied";
    public static final String ACEGI_SECURITY_AUTHENTICATION_CONTEXT_KEY = "ACEGI_SECURITY_AUTHENTICATION_CONTEXT";

    //~ Instance fields ========================================================

    /**
     * Indicates if this filter can create a <code>HttpSession</code> if needed
     * (sessions are always created sparingly, but setting this value to false
     * will prohibit sessions from ever being created). Defaults to true.
     */
    private boolean allowSessionCreation = true;

    //~ Methods ================================================================

    public void setAllowSessionCreation(boolean allowSessionCreation) {
        this.allowSessionCreation = allowSessionCreation;
    }

    public boolean isAllowSessionCreation() {
        return allowSessionCreation;
    }

    /**
     * Does nothing. We use IoC container lifecycle services instead.
     */
    public void destroy() {}

    public void doFilter(ServletRequest request, ServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        if ((request != null) && (request.getAttribute(FILTER_APPLIED) != null)) {
            // ensure that filter is only applied once per request
            chain.doFilter(request, response);
        } else {
            if (request != null) {
                request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
            }

            // Nullify the ThreadLocal if it currently contains data (it shouldn't)
            if (SecurityContext.getAuthentication() != null) {
                if (logger.isWarnEnabled()) {
                    logger.warn(
                        "SecurityContext should have been null but contained: '"
                        + SecurityContext.getAuthentication()
                        + "'; setting to null now");
                }

                SecurityContext.setAuthentication(null);
            }

            HttpSession httpSession = null;
            boolean httpSessionExistedAtStartOfRequest = false;

            try {
                httpSession = ((HttpServletRequest) request).getSession(false);
            } catch (IllegalStateException ignored) {}

            if (httpSession != null) {
                httpSessionExistedAtStartOfRequest = true;

                Object authenticationObject = httpSession.getAttribute(ACEGI_SECURITY_AUTHENTICATION_CONTEXT_KEY);

                if (authenticationObject != null) {
                    // HttpSession provided an Authentication object
                    if (authenticationObject instanceof Authentication) {
                        if (logger.isDebugEnabled()) {
                            logger.debug(
                                "Obtained from ACEGI_SECURITY_AUTHENTICATION_CONTEXT a valid Authentication and set to SecurityContext: '"
                                + authenticationObject + "'");
                        }

                        SecurityContext.setAuthentication((Authentication) authenticationObject);
                    } else {
                        if (logger.isWarnEnabled()) {
                            logger.warn(
                                "ACEGI_SECURITY_AUTHENTICATION_CONTEXT did not contain an Authentication but contained: '"
                                + authenticationObject
                                + "'; are you improperly modifying the HttpSession directly (you should always use SecurityContext) or using the HttpSession attribute reserved for this class?");
                        }
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(
                            "HttpSession returned null object for ACEGI_SECURITY_AUTHENTICATION_CONTEXT");
                    }
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug("No HttpSession currently exists");
                }
            }

            // Make the HttpSession null, as we want to ensure we don't keep any
            // reference to the HttpSession laying around in memory (in case the
            // chain.doFilter() we're about to invoke decides to invalidate it).
            httpSession = null;

            // Proceed with chain
            chain.doFilter(request, response);

            // Store Authentication back to HttpSession
            try {
                httpSession = ((HttpServletRequest) request).getSession(false);
            } catch (IllegalStateException ignored) {}

            if ((httpSession == null) && httpSessionExistedAtStartOfRequest) {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "HttpSession is now null, but was not null at start of request; session was invalidated during filter chain, so we will NOT create a new session now");
                }
            }

            // Generate a HttpSession *only* if we have to
            if ((httpSession == null) && !httpSessionExistedAtStartOfRequest) {
                if (!allowSessionCreation) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(
                            "The HttpSessionContextIntegrationFilter is prohibited from creating a HttpSession by the allowSessionCreation property being false");
                    }
                } else if (SecurityContext.getAuthentication() != null) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(
                            "HttpSession being created as SecurityContext contents are non-null");
                    }

                    try {
                        httpSession = ((HttpServletRequest) request).getSession(true);
                    } catch (IllegalStateException ignored) {}
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(
                            "SecurityContext contents and HttpSession are both null; not creating HttpSession");
                    }
                }
            }

            // If HttpSession exists or was just created, store current SecurityContext contents
            if (httpSession != null) {
                httpSession.setAttribute(ACEGI_SECURITY_AUTHENTICATION_CONTEXT_KEY,
                    SecurityContext.getAuthentication());

                if (logger.isDebugEnabled()) {
                    logger.debug("SecurityContext stored to HttpSession: '"
                        + SecurityContext.getAuthentication() + "'");
                }
            }

            // Remove SecurityContext contents, ready for next request
            SecurityContext.setAuthentication(null);

            if (logger.isDebugEnabled()) {
                logger.debug(
                    "SecurityContext set to null as request processing completed");
            }
        }
    }

    /**
     * Does nothing. We use IoC container lifecycle services instead.
     *
     * @param filterConfig ignored
     *
     * @throws ServletException ignored
     */
    public void init(FilterConfig filterConfig) throws ServletException {}
}
