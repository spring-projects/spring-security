/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Abstract processor of browser-based HTTP-based authentication requests.
 *
 * <h3>Authentication Process</h3>
 *
 * The filter requires that you set the <tt>authenticationManager</tt> property. An <tt>AuthenticationManager</tt> is
 * required to process the authentication request tokens created by implementing classes.
 * <p>
 * This filter will intercept a request and attempt to perform authentication from that request if
 * the request matches the {@link #setRequiresAuthenticationRequestMatcher(RequestMatcher)}.
 * <p>
 * Authentication is performed by the {@link #attemptAuthentication(HttpServletRequest, HttpServletResponse)
 * attemptAuthentication} method, which must be implemented by subclasses.
 *
 * <h4>Authentication Success</h4>
 *
 * If authentication is successful, the resulting {@link Authentication} object will be placed into the
 * <code>SecurityContext</code> for the current thread, which is guaranteed to have already been created by an earlier
 * filter.
 * <p>
 * The configured {@link #setAuthenticationSuccessHandler(AuthenticationSuccessHandler) AuthenticationSuccessHandler} will
 * then be called to take the redirect to the appropriate destination after a successful login. The default behaviour
 * is implemented in a {@link SavedRequestAwareAuthenticationSuccessHandler} which will make use of any
 * <tt>DefaultSavedRequest</tt> set by the <tt>ExceptionTranslationFilter</tt> and redirect the user to the URL contained
 * therein. Otherwise it will redirect to the webapp root "/". You can customize this behaviour by injecting a
 * differently configured instance of this class, or by using a different implementation.
 * <p>
 * See the {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, Authentication)
 * successfulAuthentication} method for more information.
 *
 * <h4>Authentication Failure</h4>
 *
 * If authentication fails, it will delegate to the configured {@link AuthenticationFailureHandler} to allow the
 * failure information to be conveyed to the client. The default implementation is
 * {@link SimpleUrlAuthenticationFailureHandler}, which sends a 401 error code to the client. It may also be configured
 * with a failure URL as an alternative. Again you can inject whatever behaviour you require here.
 *
 * <h4>Event Publication</h4>
 *
 * If authentication is successful, an {@link InteractiveAuthenticationSuccessEvent} will be published via the
 * application context. No events will be published if authentication was unsuccessful, because this would generally be
 * recorded via an {@code AuthenticationManager}-specific application event.
 *
 * <h4>Session Authentication</h4>
 *
 * The class has an optional {@link SessionAuthenticationStrategy} which will be invoked immediately after a
 * successful call to {@code attemptAuthentication()}. Different implementations
 * {@link #setSessionAuthenticationStrategy(SessionAuthenticationStrategy) can be injected} to enable things like
 * session-fixation attack prevention or to control the number of simultaneous sessions a principal may have.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public abstract class AbstractAuthenticationProcessingFilter extends GenericFilterBean implements
        ApplicationEventPublisherAware, MessageSourceAware {
    //~ Static fields/initializers =====================================================================================

    /**
     * @deprecated Use the value in {@link WebAttributes} directly.
     */
    @Deprecated
    public static final String SPRING_SECURITY_LAST_EXCEPTION_KEY = WebAttributes.AUTHENTICATION_EXCEPTION;

    //~ Instance fields ================================================================================================

    protected ApplicationEventPublisher eventPublisher;
    protected AuthenticationDetailsSource<HttpServletRequest,?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private AuthenticationManager authenticationManager;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private RememberMeServices rememberMeServices = new NullRememberMeServices();

    private RequestMatcher requiresAuthenticationRequestMatcher;

    /**
     * The URL destination that this filter intercepts and processes (usually
     * something like <code>/j_spring_security_check</code>)
     * @deprecated use {@link #requiresAuthenticationRequestMatcher} instead
     */
    @Deprecated
    private String filterProcessesUrl;

    private boolean continueChainBeforeSuccessfulAuthentication = false;

    private SessionAuthenticationStrategy sessionStrategy = new NullAuthenticatedSessionStrategy();

    private boolean allowSessionCreation = true;

    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

    //~ Constructors ===================================================================================================

    /**
     * @param defaultFilterProcessesUrl the default value for <tt>filterProcessesUrl</tt>.
     */
    protected AbstractAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
        this.requiresAuthenticationRequestMatcher = new FilterProcessUrlRequestMatcher(defaultFilterProcessesUrl);
        this.filterProcessesUrl = defaultFilterProcessesUrl;
    }

    /**
     * Creates a new instance
     *
     * @param requiresAuthenticationRequestMatcher
     *            the {@link RequestMatcher} used to determine if authentication
     *            is required. Cannot be null.
     */
    protected AbstractAuthenticationProcessingFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        Assert.notNull(requiresAuthenticationRequestMatcher, "requiresAuthenticationRequestMatcher cannot be null");
        this.requiresAuthenticationRequestMatcher = requiresAuthenticationRequestMatcher;
    }

    //~ Methods ========================================================================================================

    @Override
    public void afterPropertiesSet() {
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
     * The configured {@link SessionAuthenticationStrategy} will be invoked (to handle any session-related behaviour
     * such as creating a new session to protect against session-fixation attacks) followed by the invocation of
     * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, Authentication)
     * successfulAuthentication} method</li>
     * <li>An <tt>AuthenticationException</tt> occurs during authentication.
     * The {@link #unsuccessfulAuthentication(HttpServletRequest, HttpServletResponse, AuthenticationException)
     * unsuccessfulAuthentication} method will be invoked</li>
     * <li>Null is returned, indicating that the authentication process is incomplete.
     * The method will then return immediately, assuming that the subclass has done any necessary work (such as
     * redirects) to continue the authentication process. The assumption is that a later request will be received
     * by this method where the returned <tt>Authentication</tt> object is not null.
     * </ol>
     */
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

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
            sessionStrategy.onAuthentication(authResult, request, response);
        } catch(InternalAuthenticationServiceException failed) {
            logger.error("An internal error occurred while trying to authenticate the user.", failed);
            unsuccessfulAuthentication(request, response, failed);

            return;
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

        successfulAuthentication(request, response, chain, authResult);
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
     * @deprecated use {@link #setRequiresAuthenticationRequestMatcher(RequestMatcher)} instead
     */
    @Deprecated
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        return requiresAuthenticationRequestMatcher.matches(request);
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
     * <li>Informs the configured <tt>RememberMeServices</tt> of the successful login</li>
     * <li>Fires an {@link InteractiveAuthenticationSuccessEvent} via the configured
     * <tt>ApplicationEventPublisher</tt></li>
     * <li>Delegates additional behaviour to the {@link AuthenticationSuccessHandler}.</li>
     * </ol>
     *
     * Subclasses can override this method to continue the {@link FilterChain} after successful authentication.
     * @param request
     * @param response
     * @param chain
     * @param authResult the object returned from the <tt>attemptAuthentication</tt> method.
     * @throws IOException
     * @throws ServletException
     */
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException{
        successfulAuthentication(request, response, authResult);
    }

    /**
     * Default behaviour for successful authentication.
     * <ol>
     * <li>Sets the successful <tt>Authentication</tt> object on the {@link SecurityContextHolder}</li>
     * <li>Informs the configured <tt>RememberMeServices</tt> of the successful login</li>
     * <li>Fires an {@link InteractiveAuthenticationSuccessEvent} via the configured
     * <tt>ApplicationEventPublisher</tt></li>
     * <li>Delegates additional behaviour to the {@link AuthenticationSuccessHandler}.</li>
     * </ol>
     *
     * @param authResult the object returned from the <tt>attemptAuthentication</tt> method.
     * @deprecated since 3.1. Use {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)} instead.
     */
    @Deprecated
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            Authentication authResult) throws IOException, ServletException {

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success. Updating SecurityContextHolder to contain: " + authResult);
        }

        SecurityContextHolder.getContext().setAuthentication(authResult);

        rememberMeServices.loginSuccess(request, response, authResult);

        // Fire event
        if (this.eventPublisher != null) {
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
        }

        successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    /**
     * Default behaviour for unsuccessful authentication.
     * <ol>
     * <li>Clears the {@link SecurityContextHolder}</li>
     * <li>Stores the exception in the session (if it exists or <tt>allowSesssionCreation</tt> is set to <tt>true</tt>)</li>
     * <li>Informs the configured <tt>RememberMeServices</tt> of the failed login</li>
     * <li>Delegates additional behaviour to the {@link AuthenticationFailureHandler}.</li>
     * </ol>
     */
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication request failed: " + failed.toString());
            logger.debug("Updated SecurityContextHolder to contain null Authentication");
            logger.debug("Delegating to authentication failure handler " + failureHandler);
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

    @Deprecated
    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    /**
     * Sets the URL that determines if authentication is required
     *
     * @param filterProcessesUrl
     * @deprecated use {@link #setRequiresAuthenticationRequestMatcher(RequestMatcher)} instead
     */
    @Deprecated
    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.requiresAuthenticationRequestMatcher = new FilterProcessUrlRequestMatcher(filterProcessesUrl);
        this.filterProcessesUrl = filterProcessesUrl;
    }

    public final void setRequiresAuthenticationRequestMatcher(RequestMatcher requestMatcher) {
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        this.filterProcessesUrl = null;
        this.requiresAuthenticationRequestMatcher = requestMatcher;
    }

    public RememberMeServices getRememberMeServices() {
        return rememberMeServices;
    }

    public void setRememberMeServices(RememberMeServices rememberMeServices) {
        Assert.notNull("rememberMeServices cannot be null");
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

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest,?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    protected boolean getAllowSessionCreation() {
        return allowSessionCreation;
    }

    public void setAllowSessionCreation(boolean allowSessionCreation) {
        this.allowSessionCreation = allowSessionCreation;
    }

    /**
     * The session handling strategy which will be invoked immediately after an authentication request is
     * successfully processed by the <tt>AuthenticationManager</tt>. Used, for example, to handle changing of the
     * session identifier to prevent session fixation attacks.
     *
     * @param sessionStrategy the implementation to use. If not set a null implementation is
     * used.
     */
    public void setSessionAuthenticationStrategy(SessionAuthenticationStrategy sessionStrategy) {
        this.sessionStrategy = sessionStrategy;
    }

    /**
     * Sets the strategy used to handle a successful authentication.
     * By default a {@link SavedRequestAwareAuthenticationSuccessHandler} is used.
     */
    public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler successHandler) {
        Assert.notNull(successHandler, "successHandler cannot be null");
        this.successHandler = successHandler;
    }

    public void setAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
        Assert.notNull(failureHandler, "failureHandler cannot be null");
        this.failureHandler = failureHandler;
    }

    protected AuthenticationSuccessHandler getSuccessHandler() {
        return successHandler;
    }

    protected AuthenticationFailureHandler getFailureHandler() {
        return failureHandler;
    }

    private static final class FilterProcessUrlRequestMatcher implements RequestMatcher {
        private final String filterProcessesUrl;

        private FilterProcessUrlRequestMatcher(String filterProcessesUrl) {
            Assert.hasLength(filterProcessesUrl, "filterProcessesUrl must be specified");
            Assert.isTrue(UrlUtils.isValidRedirectUrl(filterProcessesUrl), filterProcessesUrl + " isn't a valid redirect URL");
            this.filterProcessesUrl = filterProcessesUrl;
        }

        public boolean matches(HttpServletRequest request) {
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
    }
}
