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
import javax.servlet.http.HttpSession;


/**
 * <p>
 * Populates the <code>SecurityContextHolder</code> with information obtained
 * from the <code>HttpSession</code>.
 * </p>
 * 
 * <p>
 * The <code>HttpSession</code> will be queried to retrieve the
 * <code>SecurityContext</code> that should be stored against the
 * <code>SecurityContextHolder</code> for the duration of the web request. At
 * the end of the web request, any updates made to the
 * <code>SecurityContextHolder</code> will be persisted back to the
 * <code>HttpSession</code> by this filter.
 * </p>
 * 
 * <p>
 * If a valid <code>SecurityContext</code> cannot be obtained from the
 * <code>HttpSession</code> for whatever reason, a fresh
 * <code>SecurityContext</code> will be created and used instead.  The created
 * object will be of the instance defined by the {@link #setContext(Class)}
 * method (which defaults to {@link
 * net.sf.acegisecurity.context.SecurityContextImpl}.
 * </p>
 * 
 * <p>
 * No <code>HttpSession</code> will be created by this filter if one does not
 * already exist. If at the end of the web request the
 * <code>HttpSession</code> does not exist, a <code>HttpSession</code> will
 * <b>only</b> be created if the current contents of
 * <code>ContextHolder</code> are not {@link
 * java.lang.Object#equals(java.lang.Object)} to a <code>new</code> instance
 * of {@link #setContext(Class)}. This avoids needless
 * <code>HttpSession</code> creation, but automates the storage of changes
 * made to the <code>ContextHolder</code>.
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
 * memory and ensure all classes using the <code>ContextHolder</code> are
 * designed to have no persistence of the <code>Context</code> between web
 * requests.
 * </p>
 * 
 * <p>
 * This filter MUST be executed BEFORE any authentication procesing mechanisms.
 * Authentication processing mechanisms (eg BASIC, CAS processing filters etc)
 * expect the <code>ContextHolder</code> to contain a valid
 * <code>SecureContext</code> by the time they execute.
 * </p>
 *
 * @author Ben Alex
 * @author Patrick Burleson
 * @version $Id$
 */
public class HttpSessionContextIntegrationFilter implements InitializingBean,
    Filter {
    //~ Static fields/initializers =============================================

    protected static final Log logger = LogFactory.getLog(HttpSessionContextIntegrationFilter.class);
    private static final String FILTER_APPLIED = "__acegi_session_integration_filter_applied";
    public static final String ACEGI_SECURITY_CONTEXT_KEY = "ACEGI_SECURITY_CONTEXT";

    //~ Instance fields ========================================================

    private Class context = SecurityContextImpl.class;
    private Object contextObject;

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

    public void setContext(Class secureContext) {
        this.context = secureContext;
    }

    public Class getContext() {
        return context;
    }

    public void afterPropertiesSet() throws Exception {
        if ((this.context == null)
            || (!SecurityContext.class.isAssignableFrom(this.context))) {
            throw new IllegalArgumentException(
                "context must be defined and implement SecurityContext (typically use net.sf.acegisecurity.context.SecurityContextImpl)");
        }

        this.contextObject = generateNewContext();
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

            HttpSession httpSession = null;
            boolean httpSessionExistedAtStartOfRequest = false;

            try {
                httpSession = ((HttpServletRequest) request).getSession(false);
            } catch (IllegalStateException ignored) {}

            if (httpSession != null) {
                httpSessionExistedAtStartOfRequest = true;

                Object contextFromSessionObject = httpSession.getAttribute(ACEGI_SECURITY_CONTEXT_KEY);

                if (contextFromSessionObject != null) {
                    if (contextFromSessionObject instanceof SecurityContext) {
                        if (logger.isDebugEnabled()) {
                            logger.debug(
                                "Obtained from ACEGI_SECURITY_CONTEXT a valid SecurityContext and set to SecurityContextHolder: '"
                                + contextFromSessionObject + "'");
                        }

                        SecurityContextHolder.setContext((SecurityContext) contextFromSessionObject);
                    } else {
                        if (logger.isWarnEnabled()) {
                            logger.warn(
                                "ACEGI_SECURITY_CONTEXT did not contain a SecurityContext but contained: '"
                                + contextFromSessionObject
                                + "'; are you improperly modifying the HttpSession directly (you should always use SecurityContextHolder) or using the HttpSession attribute reserved for this class? - new SecurityContext instance associated with SecurityContextHolder");
                        }

                        SecurityContextHolder.setContext(generateNewContext());
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(
                            "HttpSession returned null object for ACEGI_SECURITY_CONTEXT - new SecurityContext instance associated with SecurityContextHolder");
                    }

                    SecurityContextHolder.setContext(generateNewContext());
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "No HttpSession currently exists - new SecurityContext instance associated with SecurityContextHolder");
                }

                SecurityContextHolder.setContext(generateNewContext());
            }

            // Make the HttpSession null, as we want to ensure we don't keep
            // a reference to the HttpSession laying around in case the
            // chain.doFilter() invalidates it.
            httpSession = null;

            // Proceed with chain
            try {
                chain.doFilter(request, response);
            } catch (IOException ioe) {
                throw ioe;
            } catch (ServletException se) {
                throw se;
            } finally {
                // do clean up, even if there was an exception
                // Store context back to HttpSession
                try {
                    httpSession = ((HttpServletRequest) request).getSession(false);
                } catch (IllegalStateException ignored) {}

                if ((httpSession == null) && httpSessionExistedAtStartOfRequest) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(
                            "HttpSession is now null, but was not null at start of request; session was invalidated, so do not create a new session");
                    }
                }

                // Generate a HttpSession only if we need to
                if ((httpSession == null)
                    && !httpSessionExistedAtStartOfRequest) {
                    if (!allowSessionCreation) {
                        if (logger.isDebugEnabled()) {
                            logger.debug(
                                "The HttpSession is currently null, and the HttpSessionContextIntegrationFilter is prohibited from creating a HttpSession (because the allowSessionCreation property is false) - SecurityContext thus not stored for next request");
                        }
                    } else if (!contextObject.equals(
                            SecurityContextHolder.getContext())) {
                        if (logger.isDebugEnabled()) {
                            logger.debug(
                                "HttpSession being created as SecurityContextHolder contents are non-default");
                        }

                        try {
                            httpSession = ((HttpServletRequest) request)
                                .getSession(true);
                        } catch (IllegalStateException ignored) {}
                    } else {
                        if (logger.isDebugEnabled()) {
                            logger.debug(
                                "HttpSession is null, but SecurityContextHolder has not changed from default: ' "
                                + SecurityContextHolder.getContext()
                                + "'; not creating HttpSession or storing SecurityContextHolder contents");
                        }
                    }
                }

                // If HttpSession exists, store current SecurityContextHolder contents
                if (httpSession != null) {
                    httpSession.setAttribute(ACEGI_SECURITY_CONTEXT_KEY,
                        SecurityContextHolder.getContext());

                    if (logger.isDebugEnabled()) {
                        logger.debug("SecurityContext stored to HttpSession: '"
                            + SecurityContextHolder.getContext() + "'");
                    }
                }

                // Remove SecurityContextHolder contents
                SecurityContextHolder.setContext(generateNewContext());

                if (logger.isDebugEnabled()) {
                    logger.debug(
                        "SecurityContextHolder set to new context, as request processing completed");
                }
            }
        }
    }

    public SecurityContext generateNewContext() throws ServletException {
        try {
            return (SecurityContext) this.context.newInstance();
        } catch (InstantiationException ie) {
            throw new ServletException(ie);
        } catch (IllegalAccessException iae) {
            throw new ServletException(iae);
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
