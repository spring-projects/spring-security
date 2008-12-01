package org.springframework.security.context;

import java.lang.reflect.Method;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.AuthenticationTrustResolver;
import org.springframework.security.AuthenticationTrustResolverImpl;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;

/**
 * A <tt>SecurityContextRepository</tt> implementation which stores the security context in the HttpSession between
 * requests.
 * <p>
 * The <code>HttpSession</code> will be queried to retrieve the <code>SecurityContext</code> in the <tt>loadContext</tt>
 * method (using the key {@link #SPRING_SECURITY_CONTEXT_KEY}). If a valid <code>SecurityContext</code> cannot be
 * obtained from the <code>HttpSession</code> for whatever reason, a fresh <code>SecurityContext</code> will be created
 * and returned instead. The created object will be an instance of the class set using the
 * {@link #setContextClass(Class)} method. If this hasn't been set, a {@link SecurityContextImpl} will be returned.
 * <p>
 * When <tt>saveContext</tt> is called, the context will be stored under the same key, provided
 * <ol>
 * <li>The value has changed</li>
 * <li>The configured <tt>AuthenticationTrustResolver</tt> does not report that the contents represent an anonymous
 * user</li>
 * </ol>
 * <p>
 * With the standard configuration, no <code>HttpSession</code> will be created during <tt>loadContext</tt> if one does
 * not already exist. When <tt>saveContext</tt> is called at the end of the web request, and no session exists, a new
 * <code>HttpSession</code> will <b>only</b> be created if the supplied <tt>SecurityContext</tt> is not equal
 * to a <code>new</code> instance of the {@link #setContextClass(Class) contextClass} (or an empty
 * <tt>SecurityContextImpl</tt> if the class has not been set. This avoids needless <code>HttpSession</code> creation,
 * but automates the storage of changes made to the context during the request. Note that if
 * {@link SecurityContextPersistenceFilter} is configured to eagerly create sessions, then the session-minimisation
 * logic applied here will not make any difference. If you are using eager session creation, then you should
 * ensure that the <tt>allowSessionCreation</tt> property of this class is set to <tt>true</tt> (the default).
 * <p>
 * If for whatever reason no <code>HttpSession</code> should <b>ever</b> be created (e.g. Basic authentication is being
 * used or similar clients that will never present the same <code>jsessionid</code> etc), then
 * {@link #setAllowSessionCreation(boolean) allowSessionCreation} should be set to <code>false</code>.
 * Only do this if you really need to conserve server memory and ensure all classes using the
 * <code>SecurityContextHolder</code> are designed to have no persistence of the <code>SecurityContext</code>
 * between web requests.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class HttpSessionSecurityContextRepository implements SecurityContextRepository {
    public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

    protected final Log logger = LogFactory.getLog(this.getClass());

    private Class<? extends SecurityContext> securityContextClass = null;
    /** SecurityContext instance used to check for equality with default (unauthenticated) content */
    private Object contextObject = new SecurityContextImpl();
    private boolean cloneFromHttpSession = false;
    private boolean allowSessionCreation = true;

    private AuthenticationTrustResolver authenticationTrustResolver = new AuthenticationTrustResolverImpl();

    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        HttpServletResponse response = requestResponseHolder.getResponse();
        HttpSession httpSession = request.getSession(false);

        SecurityContext context = readSecurityContextFromSession(httpSession);

        if (context == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("No SecurityContext was available from the HttpSession: " + httpSession +". " +
                        "A new one will be created.");
            }
            context = generateNewContext();

        }

        requestResponseHolder.setResponse(new SaveToSessionResponseWrapper(response, request,
                httpSession != null, context.hashCode()));

        return context;
    }

    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        SaveToSessionResponseWrapper responseWrapper = (SaveToSessionResponseWrapper)response;
        // saveContext() might already be called by the response wrapper
        // if something in the chain called sendError() or sendRedirect(). This ensures we only call it
        // once per request.
        if (!responseWrapper.isContextSaved() ) {
            responseWrapper.saveContext(context);
        }
    }



    /**
     * Gets the security context from the session (if available) and returns it.
     * <p>
     * If the session is null, the context object is null or the context object stored in the session
     * is not an instance of SecurityContext it will return null.
     * <p>
     * If <tt>cloneFromHttpSession</tt> is set to true, it will attempt to clone the context object
     * and return the cloned instance.
     *
     * @param httpSession the session obtained from the request.
     */
    private SecurityContext readSecurityContextFromSession(HttpSession httpSession) {
        if (httpSession == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("No HttpSession currently exists");
            }

            return null;
        }

        // Session exists, so try to obtain a context from it.

        Object contextFromSession = httpSession.getAttribute(SPRING_SECURITY_CONTEXT_KEY);

        if (contextFromSession == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("HttpSession returned null object for SPRING_SECURITY_CONTEXT");
            }

            return null;
        }

        // We now have the security context object from the session.
        if (!(contextFromSession instanceof SecurityContext)) {
            if (logger.isWarnEnabled()) {
                logger.warn("SPRING_SECURITY_CONTEXT did not contain a SecurityContext but contained: '"
                        + contextFromSession + "'; are you improperly modifying the HttpSession directly "
                        + "(you should always use SecurityContextHolder) or using the HttpSession attribute "
                        + "reserved for this class?");
            }

            return null;
        }

        // Clone if required (see SEC-356)
        if (cloneFromHttpSession) {
            contextFromSession = cloneContext(contextFromSession);
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Obtained a valid SecurityContext from SPRING_SECURITY_CONTEXT: '" + contextFromSession + "'");
        }

        // Everything OK. The only non-null return from this method.

        return (SecurityContext) contextFromSession;
    }

    /**
     *
     * @param context the object which was stored under the security context key in the HttpSession.
     * @return the cloned SecurityContext object. Never null.
     */
    private Object cloneContext(Object context) {
        Object clonedContext = null;
        Assert.isInstanceOf(Cloneable.class, context,
                "Context must implement Cloneable and provide a Object.clone() method");
        try {
            Method m = context.getClass().getMethod("clone", new Class[]{});
            if (!m.isAccessible()) {
                m.setAccessible(true);
            }
            clonedContext = m.invoke(context, new Object[]{});
        } catch (Exception ex) {
            ReflectionUtils.handleReflectionException(ex);
        }

        return clonedContext;
    }

    /**
     * By default, returns an instance of {@link SecurityContextImpl}.
     * If a custom <tt>SecurityContext</tt> implementation is in use (i.e. the <tt>securityContextClass</tt> property
     * is set), it will attempt to invoke the no-args constructor on the supplied class instead and return the created
     * instance.
     *
     * @return a new SecurityContext instance. Never null.
     */
    SecurityContext generateNewContext() {
        if (securityContextClass == null) {
            return new SecurityContextImpl();
        }

        SecurityContext context = null;
        try {
            context = securityContextClass.newInstance();
        } catch (Exception e) {
            ReflectionUtils.handleReflectionException(e);
        }
        return context;
    }

    @SuppressWarnings("unchecked")
    public void setSecurityContextClass(Class contextClass) {
        if (contextClass == null || (!SecurityContext.class.isAssignableFrom(contextClass))) {
            throw new IllegalArgumentException("securityContextClass must implement SecurityContext "
                    + "(typically use org.springframework.security.context.SecurityContextImpl; existing class is "
                    + contextClass + ")");
        }

        this.securityContextClass = contextClass;
        contextObject = generateNewContext();
    }

    public void setCloneFromHttpSession(boolean cloneFromHttpSession) {
        this.cloneFromHttpSession = cloneFromHttpSession;
    }

    public void setAllowSessionCreation(boolean allowSessionCreation) {
        this.allowSessionCreation = allowSessionCreation;
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Wrapper that is applied to every request/response to update the <code>HttpSession<code> with
     * the <code>SecurityContext</code> when a <code>sendError()</code> or <code>sendRedirect</code>
     * happens. See SEC-398.
     * <p>
     * Stores the necessary state from the start of the request in order to make a decision about whether
     * the security context has changed before saving it.
     */
    class SaveToSessionResponseWrapper extends SaveContextOnUpdateOrErrorResponseWrapper {

        private HttpServletRequest request;
        private boolean httpSessionExistedAtStartOfRequest;
        private int contextHashBeforeChainExecution;

        /**
         * Takes the parameters required to call <code>saveContext()</code> successfully in
         * addition to the request and the response object we are wrapping.
         *
         * @param request the request object (used to obtain the session, if one exists).
         * @param httpSessionExistedAtStartOfRequest indicates whether there was a session in place before the
         *        filter chain executed. If this is true, and the session is found to be null, this indicates that it was
         *        invalidated during the request and a new session will now be created.
         * @param contextHashBeforeChainExecution the hashcode of the context before the filter chain executed.
         *        The context will only be stored if it has a different hashcode, indicating that the context changed
         *        during the request.
         */
        SaveToSessionResponseWrapper(HttpServletResponse response, HttpServletRequest request,
                                                      boolean httpSessionExistedAtStartOfRequest,
                                                      int contextHashBeforeChainExecution) {
            super(response);
            this.request = request;
            this.httpSessionExistedAtStartOfRequest = httpSessionExistedAtStartOfRequest;
            this.contextHashBeforeChainExecution = contextHashBeforeChainExecution;
        }

        /**
         * Stores the supplied security context in the session (if available) and if it has changed since it was
         * set at the start of the request. If the AuthenticationTrustResolver identifies the current user as
         * anonymous, then the context will not be stored.
         *
         * @param context the context object obtained from the SecurityContextHolder after the request has
         *        been processed by the filter chain. SecurityContextHolder.getContext() cannot be used to obtain
         *        the context as it has already been cleared by the time this method is called.
         *
         */
        @Override
        void saveContext(SecurityContext context) {
            HttpSession httpSession = request.getSession(false);

            if (httpSession == null) {
                if (httpSessionExistedAtStartOfRequest) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("HttpSession is now null, but was not null at start of request; "
                                + "session was invalidated, so do not create a new session");
                    }
                } else {
                    // Generate a HttpSession only if we need to

                    if (!allowSessionCreation) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("The HttpSession is currently null, and the "
                                            + "HttpSessionContextIntegrationFilter is prohibited from creating an HttpSession "
                                            + "(because the allowSessionCreation property is false) - SecurityContext thus not "
                                            + "stored for next request");
                        }
                    } else if (!contextObject.equals(context)) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("HttpSession being created as SecurityContextHolder contents are non-default");
                        }

                        try {
                            httpSession = request.getSession(true);
                        } catch (IllegalStateException e) {
                            // Response must already be committed, therefore can't create a new session
                        }

                    } else {
                        if (logger.isDebugEnabled()) {
                            logger.debug("HttpSession is null, but SecurityContextHolder has not changed from default: ' "
                                    + context
                                    + "'; not creating HttpSession or storing SecurityContextHolder contents");
                        }
                    }
                }
            }

            // If HttpSession exists, store current SecurityContextHolder contents but only if
            // the SecurityContext has actually changed (see JIRA SEC-37)
            if (httpSession != null && context.hashCode() != contextHashBeforeChainExecution) {
                // See SEC-766
                if (authenticationTrustResolver.isAnonymous(context.getAuthentication())) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("SecurityContext contents are anonymous - context will not be stored in HttpSession. ");
                    }
                } else {
                    httpSession.setAttribute(SPRING_SECURITY_CONTEXT_KEY, context);

                    if (logger.isDebugEnabled()) {
                        logger.debug("SecurityContext stored to HttpSession: '" + context + "'");
                    }
                }
            }
        }
    }
}
