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

import org.springframework.security.SpringSecurityMessageSource;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.util.SessionUtils;
import org.springframework.security.util.UrlUtils;

import org.springframework.security.concurrent.SessionRegistry;
import org.springframework.security.context.SecurityContextHolder;

import org.springframework.security.event.authentication.InteractiveAuthenticationSuccessEvent;

import org.springframework.security.ui.rememberme.NullRememberMeServices;
import org.springframework.security.ui.rememberme.RememberMeServices;
import org.springframework.security.ui.savedrequest.SavedRequest;

import org.springframework.beans.factory.InitializingBean;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;

import org.springframework.util.Assert;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * Abstract processor of browser-based HTTP-based authentication requests.
 * <p>
 * This filter is responsible for processing authentication requests. If
 * authentication is successful, the resulting {@link Authentication} object
 * will be placed into the <code>SecurityContext</code>, which is guaranteed
 * to have already been created by an earlier filter.
 * <p>
 * If authentication fails, the <code>AuthenticationException</code> will be
 * placed into the <code>HttpSession</code> with the attribute defined by
 * {@link #SPRING_SECURITY_LAST_EXCEPTION_KEY}.
 * <p>
 * To use this filter, it is necessary to specify the following properties:
 * <ul>
 * <li><code>authenticationFailureUrl</code> (optional) indicates the URL that should be
 * used for redirection if the authentication request fails. eg:
 * <code>/login.jsp?login_error=1</code>. If not configured, <tt>sendError</tt> will be
 * called on the response, with the error code SC_UNAUTHORIZED.</li>
 * <li><code>filterProcessesUrl</code> indicates the URL that this filter
 * will respond to. This parameter varies by subclass.</li>
 * <li><code>alwaysUseDefaultTargetUrl</code> causes successful
 * authentication to always redirect to the <code>defaultTargetUrl</code>,
 * even if the <code>HttpSession</code> attribute named {@link
 * SavedRequest# SPRING_SECURITY_SAVED_REQUEST_KEY} defines the intended target URL.</li>
 * </ul>
 * <p>
 * To configure this filter to redirect to specific pages as the result of
 * specific {@link AuthenticationException}s you can do the following.
 * Configure the <code>exceptionMappings</code> property in your application
 * xml. This property is a java.util.Properties object that maps a
 * fully-qualified exception class name to a redirection url target. For
 * example:
 *
 * <pre>
 *  &lt;property name=&quot;exceptionMappings&quot;&gt;
 *    &lt;props&gt;
 *      &lt;prop&gt; key=&quot;org.springframework.security.BadCredentialsException&quot;&gt;/bad_credentials.jsp&lt;/prop&gt;
 *    &lt;/props&gt;
 *  &lt;/property&gt;
 * </pre>
 *
 * The example above would redirect all
 * {@link org.springframework.security.BadCredentialsException}s thrown, to a page in the
 * web-application called /bad_credentials.jsp.
 * <p>
 * Any {@link AuthenticationException} thrown that cannot be matched in the
 * <code>exceptionMappings</code> will be redirected to the
 * <code>authenticationFailureUrl</code>
 * <p>
 * If authentication is successful, an {@link
 * org.springframework.security.event.authentication.InteractiveAuthenticationSuccessEvent}
 * will be published to the application context. No events will be published if
 * authentication was unsuccessful, because this would generally be recorded via
 * an <code>AuthenticationManager</code>-specific application event.
 * <p>
 * The filter has an optional attribute <tt>invalidateSessionOnSuccessfulAuthentication</tt> that will invalidate
 * the current session on successful authentication. This is to protect against session fixation attacks (see
 * <a href="http://en.wikipedia.org/wiki/Session_fixation">this Wikipedia article</a> for more information).
 * The behaviour is turned off by default. Additionally there is a property <tt>migrateInvalidatedSessionAttributes</tt>
 * which tells if on session invalidation we are to migrate all session attributes from the old session to a newly
 * created one. This is turned on by default, but not used unless <tt>invalidateSessionOnSuccessfulAuthentication</tt>
 * is true. If you are using this feature in combination with concurrent session control, you should set the
 * <tt>sessionRegistry</tt> property to make sure that the session information is updated consistently.
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractProcessingFilter extends SpringSecurityFilter implements InitializingBean,
        ApplicationEventPublisherAware, MessageSourceAware {
    //~ Static fields/initializers =====================================================================================

    public static final String SPRING_SECURITY_LAST_EXCEPTION_KEY = "SPRING_SECURITY_LAST_EXCEPTION";

    //~ Instance fields ================================================================================================

    protected ApplicationEventPublisher eventPublisher;
    protected AuthenticationDetailsSource authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private AuthenticationManager authenticationManager;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    /*
     * Delay use of NullRememberMeServices until initialization so that namespace has a chance to inject
     * the RememberMeServices implementation into custom implementations.
     */
    private RememberMeServices rememberMeServices = null;

    /**
     * The URL destination that this filter intercepts and processes (usually
     * something like <code>/j_spring_security_check</code>)
     */
    private String filterProcessesUrl = getDefaultFilterProcessesUrl();

    private boolean continueChainBeforeSuccessfulAuthentication = false;

    /**
     * Tells if we on successful authentication should invalidate the
     * current session. This is a common guard against session fixation attacks.
     * Defaults to <code>false</code>.
     */
    private boolean invalidateSessionOnSuccessfulAuthentication = false;

    /**
     * If {@link #invalidateSessionOnSuccessfulAuthentication} is true, this
     * flag indicates that the session attributes of the session to be invalidated
     * are to be migrated to the new session. Defaults to <code>true</code> since
     * nothing will happen unless {@link #invalidateSessionOnSuccessfulAuthentication}
     * is true.
     */
    private boolean migrateInvalidatedSessionAttributes = true;

    private boolean allowSessionCreation = true;

    private SessionRegistry sessionRegistry;

    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

    //~ Methods ========================================================================================================

    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(filterProcessesUrl, "filterProcessesUrl must be specified");
        Assert.isTrue(UrlUtils.isValidRedirectUrl(filterProcessesUrl), filterProcessesUrl + " isn't a valid redirect URL");
        Assert.notNull(authenticationManager, "authenticationManager must be specified");

        if (rememberMeServices == null) {
            rememberMeServices = new NullRememberMeServices();
        }
    }

    /**
     * Invokes the {@link #requiresAuthentication(HttpServletRequest, HttpServletResponse) requiresAuthentication}
     * method to determine whether the request is for authentication and should be handled by this filter.
     * If it is an authentication request, the
     * {@link #attemptAuthentication(HttpServletRequest, HttpServletResponse) attemptAuthentication} will be invoked
     * to perform the authentication. There are then three possible outcomes:
     * <ol>
     * <li>An <tt>Authentication</tt> object is returned.
     * The {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, Authentication)
     * successfulAuthentication} method will be invoked</li>
     * <li>An <tt>AuthenticationException</tt> occurs during authentication.
     * The {@link #unSuccessfulAuthentication(HttpServletRequest, HttpServletResponse, Authentication)
     * unSuccessfulAuthentication} method will be invoked</li>
     * <li>Null is returned, indicating that the authentication process is incomplete.
     * The method will then return immediately, assuming that the subclass has done any necessary work (such as
     * redirects) to continue the authentication process. The assumption is that a later request will be received
     * by this method where the returned <tt>Authentication</tt> object is not null.
     * </ol>
     */
    public void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);

            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Request is to process authentication");
        }

        Authentication authResult;

        try {
            authResult = attemptAuthentication(request, response);
            if (authResult == null) {
                // return immediately as subclass has indicated that it hasn't completed authentication
                return;
            }
        }
        catch (AuthenticationException failed) {
            // Authentication failed
            unsuccessfulAuthentication(request, response, failed);

            return;
        }

        // Authentication success
        if (continueChainBeforeSuccessfulAuthentication) {
            chain.doFilter(request, response);
        }

        successfulAuthentication(request, response, authResult);
    }

    /**
     * Indicates whether this filter should attempt to process a login request for the current invocation.
     * <p>
     * It strips any parameters from the "path" section of the request URL (such
     * as the jsessionid parameter in
     * <em>http://host/myapp/index.html;jsessionid=blah</em>) before matching
     * against the <code>filterProcessesUrl</code> property.
     * <p>
     * Subclasses may override for special requirements, such as Tapestry integration.
     *
     * @return <code>true</code> if the filter should attempt authentication, <code>false</code> otherwise.
     */
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String uri = request.getRequestURI();
        int pathParamIndex = uri.indexOf(';');

        if (pathParamIndex > 0) {
            // strip everything after the first semi-colon
            uri = uri.substring(0, pathParamIndex);
        }

        if ("".equals(request.getContextPath())) {
            return uri.endsWith(filterProcessesUrl);
        }

        return uri.endsWith(request.getContextPath() + filterProcessesUrl);
    }

    /**
     * Performs actual authentication.
     * <p>
     * The implementation should do one of the following:
     * <ol>
     * <li>Return a populated authentication token for the authenticated user, indicating successful authentication</li>
     * <li>Return null, indicating that the authentication process is still in progress. Before returning, the
     * implementation should perform any additional work required to complete the process.</li>
     * <li>Throw an <tt>AuthenticationException</tt> if the authentication process fails</li>
     * </ol>
     *
     * @param request   from which to extract parameters and perform the authentication
     * @param response  the response, which may be needed if the implementation has to do a redirect as part of a
     *                  multi-stage authentication process (such as OpenID).
     *
     * @return the authenticated user token, or null if authentication is incomplete.
     *
     * @throws AuthenticationException if authentication fails.
     */
    public abstract Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException;

    /**
     * Default behaviour for successful authentication.
     * <ol>
     * <li>Sets the successful <tt>Authentication</tt> object on the {@link SecurityContextHolder}</li>
     * <li>Performs any configured session migration behaviour</li>
     * <li>Informs the configured <tt>RememberMeServices</tt> of the successul login</li>
     * <li>Fires an {@link InteractiveAuthenticationSuccessEvent} via the configured
     * <tt>ApplicationEventPublisher</tt></li>
     * <li>Delegates additional behaviour to the {@link AuthenticationSuccessHandler}.</li>
     * </ol>
     *
     * @param authResult the object returned from the <tt>attemptAuthentication</tt> method.
     */
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            Authentication authResult) throws IOException, ServletException {

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success. Updating SecurityContextHolder to contain: " + authResult);
        }

        SecurityContextHolder.getContext().setAuthentication(authResult);

        if (invalidateSessionOnSuccessfulAuthentication) {
            SessionUtils.startNewSessionIfRequired(request, migrateInvalidatedSessionAttributes, sessionRegistry);
        }

        rememberMeServices.loginSuccess(request, response, authResult);

        // Fire event
        if (this.eventPublisher != null) {
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
        }

        successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.getContext().setAuthentication(null);

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication request failed: " + failed.toString());
            logger.debug("Updated SecurityContextHolder to contain null Authentication");
            logger.debug("Delegating to authentication failure handler" + failureHandler);
        }

        try {
            HttpSession session = request.getSession(false);

            if (session != null || allowSessionCreation) {
                request.getSession().setAttribute(SPRING_SECURITY_LAST_EXCEPTION_KEY, failed);
            }
        }
        catch (Exception ignored) {
        }

        rememberMeServices.loginFail(request, response);

        failureHandler.onAuthenticationFailure(request, response, failed);
    }

    protected AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * Specifies the default <code>filterProcessesUrl</code> for the implementation.
     *
     * @return the default <code>filterProcessesUrl</code>
     */
    public abstract String getDefaultFilterProcessesUrl();

    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.filterProcessesUrl = filterProcessesUrl;
    }

    public RememberMeServices getRememberMeServices() {
        return rememberMeServices;
    }

    public void setRememberMeServices(RememberMeServices rememberMeServices) {
        this.rememberMeServices = rememberMeServices;
    }

    /**
     * Indicates if the filter chain should be continued prior to delegation to
     * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse,
     * Authentication)}, which may be useful in certain environment (such as
     * Tapestry applications). Defaults to <code>false</code>.
     */
    public void setContinueChainBeforeSuccessfulAuthentication(boolean continueChainBeforeSuccessfulAuthentication) {
        this.continueChainBeforeSuccessfulAuthentication = continueChainBeforeSuccessfulAuthentication;
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    public void setInvalidateSessionOnSuccessfulAuthentication(boolean invalidateSessionOnSuccessfulAuthentication) {
        this.invalidateSessionOnSuccessfulAuthentication = invalidateSessionOnSuccessfulAuthentication;
    }

    public void setMigrateInvalidatedSessionAttributes(boolean migrateInvalidatedSessionAttributes) {
        this.migrateInvalidatedSessionAttributes = migrateInvalidatedSessionAttributes;
    }

    public AuthenticationDetailsSource getAuthenticationDetailsSource() {
        // Required due to SEC-310
        return authenticationDetailsSource;
    }

    protected boolean getAllowSessionCreation() {
        return allowSessionCreation;
    }

    public void setAllowSessionCreation(boolean allowSessionCreation) {
        this.allowSessionCreation = allowSessionCreation;
    }

    /**
     * The session registry needs to be set if session fixation attack protection is in use (and concurrent
     * session control is enabled).
     */
    public void setSessionRegistry(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    public void setSuccessHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    public void setFailureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
    }
}
