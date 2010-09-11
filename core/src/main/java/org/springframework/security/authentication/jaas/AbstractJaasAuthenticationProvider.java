/*
 * Copyright 2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.authentication.jaas;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationFailedEvent;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

/**
 * An {@link AuthenticationProvider} implementation that retrieves user details from a JAAS login configuration.
 *
 * <p>This <code>AuthenticationProvider</code> is capable of validating {@link
 * org.springframework.security.authentication.UsernamePasswordAuthenticationToken} requests contain the correct username and
 * password.</p>
 * <p>This implementation is backed by a <a
 * href="http://java.sun.com/j2se/1.5.0/docs/guide/security/jaas/JAASRefGuide.html">JAAS</a> configuration that is provided by
 * a subclass's implementation of {@link #createLoginContext(CallbackHandler)}.
 * 
 * <p>When using JAAS login modules as the authentication source, sometimes the
 * <a href="http://java.sun.com/j2se/1.5.0/docs/api/javax/security/auth/login/LoginContext.html">LoginContext</a> will
 * require <i>CallbackHandler</i>s. The AbstractJaasAuthenticationProvider uses an internal
 * <a href="http://java.sun.com/j2se/1.5.0/docs/api/javax/security/auth/callback/CallbackHandler.html">CallbackHandler
 * </a> to wrap the {@link JaasAuthenticationCallbackHandler}s configured in the ApplicationContext.
 * When the LoginContext calls the internal CallbackHandler, control is passed to each
 * {@link JaasAuthenticationCallbackHandler} for each Callback passed.
 * </p>
 * <p>{@link JaasAuthenticationCallbackHandler}s are passed to the AbstractJaasAuthenticationProvider through the {@link
 * #setCallbackHandlers(org.springframework.security.authentication.jaas.JaasAuthenticationCallbackHandler[]) callbackHandlers}
 * property.
 * <pre>
 * &lt;property name="callbackHandlers"&gt;
 *   &lt;list&gt;
 *     &lt;bean class="org.springframework.security.authentication.jaas.TestCallbackHandler"/&gt;
 *     &lt;bean class="{@link JaasNameCallbackHandler org.springframework.security.authentication.jaas.JaasNameCallbackHandler}"/&gt;
 *     &lt;bean class="{@link JaasPasswordCallbackHandler org.springframework.security.authentication.jaas.JaasPasswordCallbackHandler}"/&gt;
 *  &lt;/list&gt;
 * &lt;/property&gt;
 * </pre>
 * </p>
 * <p>
 * After calling LoginContext.login(), the AbstractJaasAuthenticationProvider will retrieve the returned Principals
 * from the Subject (LoginContext.getSubject().getPrincipals). Each returned principal is then passed to the
 * configured {@link AuthorityGranter}s. An AuthorityGranter is a mapping between a returned Principal, and a role
 * name. If an AuthorityGranter wishes to grant an Authorization a role, it returns that role name from it's {@link
 * AuthorityGranter#grant(java.security.Principal)} method. The returned role will be applied to the Authorization
 * object as a {@link GrantedAuthority}.</p>
 * <p>AuthorityGranters are configured in spring xml as follows...
 * <pre>
 * &lt;property name="authorityGranters"&gt;
 *   &lt;list&gt;
 *     &lt;bean class="org.springframework.security.authentication.jaas.TestAuthorityGranter"/&gt;
 *   &lt;/list&gt;
 *  &lt;/property&gt;
 * </pre>
 * 
 * @author Ray Krueger
 * @author Rob Winch
 */
public abstract class AbstractJaasAuthenticationProvider implements AuthenticationProvider,
ApplicationEventPublisherAware, InitializingBean, ApplicationListener<SessionDestroyedEvent> {
    //~ Instance fields ================================================================================================

    private ApplicationEventPublisher applicationEventPublisher;
    private AuthorityGranter[] authorityGranters;
    private JaasAuthenticationCallbackHandler[] callbackHandlers;
    protected final Log log = LogFactory.getLog(getClass());
    private LoginExceptionResolver loginExceptionResolver = new DefaultLoginExceptionResolver();
    private String loginContextName = "SPRINGSECURITY";

    //~ Methods ========================================================================================================

    /**
     * Validates the required properties are set. In addition, if
     * {@link #setCallbackHandlers(JaasAuthenticationCallbackHandler[])} has not
     * been called with valid handlers, initializes to use
     * {@link JaasNameCallbackHandler} and {@link JaasPasswordCallbackHandler}.
     */
    public void afterPropertiesSet() throws Exception {
        Assert.hasLength(loginContextName, "loginContextName cannot be null or empty");
        Assert.notEmpty(authorityGranters, "authorityGranters cannot be null or empty");
        if (ObjectUtils.isEmpty(callbackHandlers)) {
            setCallbackHandlers(new JaasAuthenticationCallbackHandler[] { new JaasNameCallbackHandler(),
                    new JaasPasswordCallbackHandler() });
        }
        Assert.notNull(loginExceptionResolver, "loginExceptionResolver cannot be null");
    }

    /**
     * Attempts to login the user given the Authentication objects principal and credential
     *
     * @param auth The Authentication object to be authenticated.
     *
     * @return The authenticated Authentication object, with it's grantedAuthorities set.
     *
     * @throws AuthenticationException This implementation does not handle 'locked' or 'disabled' accounts. This method
     *         only throws a AuthenticationServiceException, with the message of the LoginException that will be
     *         thrown, should the loginContext.login() method fail.
     */
    public Authentication authenticate(Authentication auth) throws AuthenticationException {
        if (!(auth instanceof UsernamePasswordAuthenticationToken)) {
            return null;
        }

        UsernamePasswordAuthenticationToken request = (UsernamePasswordAuthenticationToken) auth;
        Set<GrantedAuthority> authorities;

        try {
            // Create the LoginContext object, and pass our InternallCallbackHandler
            LoginContext loginContext = createLoginContext(new InternalCallbackHandler(auth));

            // Attempt to login the user, the LoginContext will call our InternalCallbackHandler at this point.
            loginContext.login();

            // Create a set to hold the authorities, and add any that have already been applied.
            authorities = new HashSet<GrantedAuthority>();
            authorities.addAll(request.getAuthorities());

            // Get the subject principals and pass them to each of the AuthorityGranters
            Set<Principal> principals = loginContext.getSubject().getPrincipals();

            for (Principal principal : principals) {
                for (AuthorityGranter granter : authorityGranters) {
                    Set<String> roles = granter.grant(principal);

                    // If the granter doesn't wish to grant any authorities, it should return null.
                    if ((roles != null) && !roles.isEmpty()) {
                        for (String role : roles) {
                            authorities.add(new JaasGrantedAuthority(role, principal));
                        }
                    }
                }
            }

            //Convert the authorities set back to an array and apply it to the token.
            JaasAuthenticationToken result = new JaasAuthenticationToken(request.getPrincipal(),
                    request.getCredentials(), new ArrayList<GrantedAuthority>(authorities), loginContext);

            //Publish the success event
            publishSuccessEvent(result);

            //we're done, return the token.
            return result;

        } catch (LoginException loginException) {
            AuthenticationException ase = loginExceptionResolver.resolveException(loginException);

            publishFailureEvent(request, ase);
            throw ase;
        }
    }

    /**
     * Creates the LoginContext to be used for authentication.
     * 
     * @param handler The CallbackHandler that should be used for the LoginContext (never <code>null</code>).
     * @return the LoginContext to use for authentication.
     * @throws LoginException
     */
    protected abstract LoginContext createLoginContext(CallbackHandler handler) throws LoginException;

    /**
     * Handles the logout by getting the SecurityContext for the session that was destroyed. <b>MUST NOT use
     * SecurityContextHolder as we are logging out a session that is not related to the current user.</b>
     *
     * @param event
     */
    protected void handleLogout(SessionDestroyedEvent event) {
        SecurityContext context = event.getSecurityContext();

        if (context == null) {
            log.debug("The destroyed session has no SecurityContext");

            return;
        }

        Authentication auth = context.getAuthentication();

        if ((auth != null) && (auth instanceof JaasAuthenticationToken)) {
            JaasAuthenticationToken token = (JaasAuthenticationToken) auth;

            try {
                LoginContext loginContext = token.getLoginContext();
                boolean debug = log.isDebugEnabled();
                if (loginContext != null) {
                    if (debug) {
                        log.debug("Logging principal: [" + token.getPrincipal() + "] out of LoginContext");
                    }
                    loginContext.logout();
                } else if (debug) {
                    log.debug("Cannot logout principal: [" + token.getPrincipal() + "] from LoginContext. "
                            + "The LoginContext is unavailable");
                }
            } catch (LoginException e) {
                log.warn("Error error logging out of LoginContext", e);
            }
        }
    }

    public void onApplicationEvent(SessionDestroyedEvent event) {
        handleLogout(event);
    }

    /**
     * Publishes the {@link JaasAuthenticationFailedEvent}. Can be overridden by subclasses for different
     * functionality
     *
     * @param token The authentication token being processed
     * @param ase The excetion that caused the authentication failure
     */
    protected void publishFailureEvent(UsernamePasswordAuthenticationToken token, AuthenticationException ase) {
        if (applicationEventPublisher != null) {
            applicationEventPublisher.publishEvent(new JaasAuthenticationFailedEvent(token, ase));
        }
    }

    /**
     * Publishes the {@link JaasAuthenticationSuccessEvent}. Can be overridden by subclasses for different
     * functionality.
     *
     * @param token The token being processed
     */
    protected void publishSuccessEvent(UsernamePasswordAuthenticationToken token) {
        if (applicationEventPublisher != null) {
            applicationEventPublisher.publishEvent(new JaasAuthenticationSuccessEvent(token));
        }
    }

    /**
     * Returns the AuthorityGrannter array that was passed to the {@link
     * #setAuthorityGranters(AuthorityGranter[])} method, or null if it none were ever set.
     *
     * @return The AuthorityGranter array, or null
     *
     * @see #setAuthorityGranters(AuthorityGranter[])
     */
    AuthorityGranter[] getAuthorityGranters() {
        return authorityGranters;
    }

    /**
     * Set the AuthorityGranters that should be consulted for role names to be granted to the Authentication.
     *
     * @param authorityGranters AuthorityGranter array
     *
     * @see JaasAuthenticationProvider
     */
    public void setAuthorityGranters(AuthorityGranter[] authorityGranters) {
        this.authorityGranters = authorityGranters;
    }

    /**
     * Returns the current JaasAuthenticationCallbackHandler array, or null if none are set.
     *
     * @return the JAASAuthenticationCallbackHandlers.
     *
     * @see #setCallbackHandlers(JaasAuthenticationCallbackHandler[])
     */
    JaasAuthenticationCallbackHandler[] getCallbackHandlers() {
        return callbackHandlers;
    }

    /**
     * Set the JAASAuthentcationCallbackHandler array to handle callback objects generated by the
     * LoginContext.login method.
     *
     * @param callbackHandlers Array of JAASAuthenticationCallbackHandlers
     */
    public void setCallbackHandlers(JaasAuthenticationCallbackHandler[] callbackHandlers) {
        this.callbackHandlers = callbackHandlers;
    }

    String getLoginContextName() {
        return loginContextName;
    }

    /**
     * Set the loginContextName, this name is used as the index to the configuration specified in the
     * loginConfig property.
     *
     * @param loginContextName
     */
    public void setLoginContextName(String loginContextName) {
        this.loginContextName = loginContextName;
    }

    LoginExceptionResolver getLoginExceptionResolver() {
        return loginExceptionResolver;
    }

    public void setLoginExceptionResolver(LoginExceptionResolver loginExceptionResolver) {
        this.loginExceptionResolver = loginExceptionResolver;
    }

    public boolean supports(Class<?> aClass) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(aClass);
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.applicationEventPublisher = applicationEventPublisher;
    }

    protected ApplicationEventPublisher getApplicationEventPublisher() {
        return applicationEventPublisher;
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Wrapper class for JAASAuthenticationCallbackHandlers
     */
    private class InternalCallbackHandler implements CallbackHandler {
        private final Authentication authentication;

        public InternalCallbackHandler(Authentication authentication) {
            this.authentication = authentication;
        }

        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            for (JaasAuthenticationCallbackHandler handler : callbackHandlers) {
                for (Callback callback : callbacks) {
                    handler.handle(callback, authentication);
                }
            }
        }
    }
}
