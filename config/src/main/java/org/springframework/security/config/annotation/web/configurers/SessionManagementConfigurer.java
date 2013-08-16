/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.util.Assert;

/**
 * Allows configuring session management.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link SessionManagementFilter}</li>
 * <li>{@link ConcurrentSessionFilter} if there are restrictions on how many concurrent sessions a user can have</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * The following shared objects are created:
 *
 * <ul>
 * <li>{@link RequestCache}</li>
 * <li>{@link SecurityContextRepository}</li>
 * <li>{@link SessionManagementConfigurer}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * <ul>
 * <li>{@link SecurityContextRepository}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 * @see SessionManagementFilter
 * @see ConcurrentSessionFilter
 */
public final class SessionManagementConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<SessionManagementConfigurer<H>,H> {
    private SessionAuthenticationStrategy sessionFixationAuthenticationStrategy = createDefaultSessionFixationProtectionStrategy();
    private SessionAuthenticationStrategy sessionAuthenticationStrategy;
    private List<SessionAuthenticationStrategy> sessionAuthenticationStrategies = new ArrayList<SessionAuthenticationStrategy>();
    private SessionRegistry sessionRegistry = new SessionRegistryImpl();
    private Integer maximumSessions;
    private String expiredUrl;
    private boolean maxSessionsPreventsLogin;
    private SessionCreationPolicy sessionPolicy = SessionCreationPolicy.IF_REQUIRED;
    private boolean enableSessionUrlRewriting;
    private String invalidSessionUrl;
    private String sessionAuthenticationErrorUrl;

    /**
     * Creates a new instance
     * @see HttpSecurity#sessionManagement()
     */
    public SessionManagementConfigurer() {
    }

    /**
     * Setting this attribute will inject the {@link SessionManagementFilter} with a
     * {@link SimpleRedirectInvalidSessionStrategy} configured with the attribute value.
     * When an invalid session ID is submitted, the strategy will be invoked,
     * redirecting to the configured URL.
     *
     * @param invalidSessionUrl the URL to redirect to when an invalid session is detected
     * @return the {@link SessionManagementConfigurer} for further customization
     */
    public SessionManagementConfigurer<H> invalidSessionUrl(String invalidSessionUrl) {
        this.invalidSessionUrl = invalidSessionUrl;
        return this;
    }

    /**
     * Defines the URL of the error page which should be shown when the
     * SessionAuthenticationStrategy raises an exception. If not set, an
     * unauthorized (402) error code will be returned to the client. Note that
     * this attribute doesn't apply if the error occurs during a form-based
     * login, where the URL for authentication failure will take precedence.
     *
     * @param sessionAuthenticationErrorUrl
     *            the URL to redirect to
     * @return the {@link SessionManagementConfigurer} for further customization
     */
    public SessionManagementConfigurer<H> sessionAuthenticationErrorUrl(String sessionAuthenticationErrorUrl) {
        this.sessionAuthenticationErrorUrl = sessionAuthenticationErrorUrl;
        return this;
    }

    /**
     * If set to true, allows HTTP sessions to be rewritten in the URLs when
     * using {@link HttpServletResponse#encodeRedirectURL(String)} or
     * {@link HttpServletResponse#encodeURL(String)}, otherwise disallows HTTP
     * sessions to be included in the URL. This prevents leaking information to
     * external domains.
     *
     * @param enableSessionUrlRewriting true if should allow the JSESSIONID to be rewritten into the URLs, else false (default)
     * @return the {@link SessionManagementConfigurer} for further customization
     * @see HttpSessionSecurityContextRepository#setDisableUrlRewriting(boolean)
     */
    public SessionManagementConfigurer<H> enableSessionUrlRewriting(boolean enableSessionUrlRewriting) {
        this.enableSessionUrlRewriting = enableSessionUrlRewriting;
        return this;
    }

    /**
     * Allows specifying the {@link SessionCreationPolicy}
     * @param sessionCreationPolicy the {@link SessionCreationPolicy} to use. Cannot be null.
     * @return the {@link SessionManagementConfigurer} for further customizations
     * @see SessionCreationPolicy
     * @throws IllegalArgumentException if {@link SessionCreationPolicy} is null.
     */
    public SessionManagementConfigurer<H> sessionCreationPolicy(SessionCreationPolicy sessionCreationPolicy) {
        Assert.notNull(sessionCreationPolicy, "sessionCreationPolicy cannot be null");
        this.sessionPolicy = sessionCreationPolicy;
        return this;
    }

    /**
     * Allows explicitly specifying the {@link SessionAuthenticationStrategy}.
     * The default is to use {@link SessionFixationProtectionStrategy}. If
     * restricting the maximum number of sessions is configured, then
     * {@link CompositeSessionAuthenticationStrategy} delegating to
     * {@link ConcurrentSessionControlAuthenticationStrategy},
     * {@link SessionFixationProtectionStrategy} (optional), and
     * {@link RegisterSessionAuthenticationStrategy} will be used.
     *
     * @param sessionAuthenticationStrategy
     * @return the {@link SessionManagementConfigurer} for further
     *         customizations
     */
    public SessionManagementConfigurer<H> sessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy) {
        this.sessionFixationAuthenticationStrategy = sessionAuthenticationStrategy;
        return this;
    }

    /**
     * Adds an additional {@link SessionAuthenticationStrategy} to be used within the {@link CompositeSessionAuthenticationStrategy}.
     *
     * @param sessionAuthenticationStrategy
     * @return the {@link SessionManagementConfigurer} for further
     *         customizations
     */
    SessionManagementConfigurer<H> addSessionAuthenticationStrategy(SessionAuthenticationStrategy sessionAuthenticationStrategy) {
        this.sessionAuthenticationStrategies.add(sessionAuthenticationStrategy);
        return this;
    }

    public SessionFixationConfigurer sessionFixation() {
        return new SessionFixationConfigurer();
    }

    /**
     * Controls the maximum number of sessions for a user. The default is to allow any number of users.
     * @param maximumSessions the maximum number of sessions for a user
     * @return the {@link SessionManagementConfigurer} for further customizations
     */
    public ConcurrencyControlConfigurer maximumSessions(int maximumSessions) {
        this.maximumSessions = maximumSessions;
        return new ConcurrencyControlConfigurer();
    }

    /**
     * Invokes {@link #postProcess(Object)} and sets the {@link SessionAuthenticationStrategy} for session fixation.
     * @param sessionFixationAuthenticationStrategy
     */
    private void setSessionFixationAuthenticationStrategy(SessionAuthenticationStrategy sessionFixationAuthenticationStrategy) {
        this.sessionFixationAuthenticationStrategy = postProcess(sessionFixationAuthenticationStrategy);
    }

    /**
     * Allows configuring SessionFixation protection
     *
     * @author Rob Winch
     */
    public final class SessionFixationConfigurer {
        /**
         * Specifies that a new session should be created, but the session
         * attributes from the original {@link HttpSession} should not be
         * retained.
         *
         * @return the {@link SessionManagementConfigurer} for further customizations
         */
        public SessionManagementConfigurer<H> newSession() {
            SessionFixationProtectionStrategy sessionFixationProtectionStrategy = new SessionFixationProtectionStrategy();
            sessionFixationProtectionStrategy.setMigrateSessionAttributes(false);
            setSessionFixationAuthenticationStrategy(sessionFixationProtectionStrategy);
            return SessionManagementConfigurer.this;
        }

        /**
         * Specifies that a new session should be created and the session
         * attributes from the original {@link HttpSession} should be
         * retained.
         *
         * @return the {@link SessionManagementConfigurer} for further customizations
         */
        public SessionManagementConfigurer<H> migrateSession() {
            setSessionFixationAuthenticationStrategy(new SessionFixationProtectionStrategy());
            return SessionManagementConfigurer.this;
        }

        /**
         * Specifies that no session fixation protection should be enabled. This
         * may be useful when utilizing other mechanisms for protecting against
         * session fixation. For example, if application container session
         * fixation protection is already in use. Otherwise, this option is not
         * recommended.
         *
         * @return the {@link SessionManagementConfigurer} for further
         *         customizations
         */
        public SessionManagementConfigurer<H> changeSessionId() {
            setSessionFixationAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
            return SessionManagementConfigurer.this;
        }

        /**
         * Specifies that no session fixation protection should be enabled. This
         * may be useful when utilizing other mechanisms for protecting against
         * session fixation. For example, if application container session
         * fixation protection is already in use. Otherwise, this option is not
         * recommended.
         *
         * @return the {@link SessionManagementConfigurer} for further
         *         customizations
         */
        public SessionManagementConfigurer<H> none() {
            setSessionFixationAuthenticationStrategy(new NullAuthenticatedSessionStrategy());
            return SessionManagementConfigurer.this;
        }
    }

    /**
     * Allows configuring controlling of multiple sessions.
     *
     * @author Rob Winch
     */
    public final class ConcurrencyControlConfigurer {

        /**
         * The URL to redirect to if a user tries to access a resource and their
         * session has been expired due to too many sessions for the current user.
         * The default is to write a simple error message to the response.
         *
         * @param expiredUrl the URL to redirect to
         * @return the {@link ConcurrencyControlConfigurer} for further customizations
         */
        public ConcurrencyControlConfigurer expiredUrl(String expiredUrl) {
            SessionManagementConfigurer.this.expiredUrl = expiredUrl;
            return this;
        }

        /**
         * If true, prevents a user from authenticating when the
         * {@link #maximumSessions(int)} has been reached. Otherwise (default), the user who
         * authenticates is allowed access and an existing user's session is
         * expired. The user's who's session is forcibly expired is sent to
         * {@link #expiredUrl(String)}. The advantage of this approach is if a user
         * accidentally does not log out, there is no need for an administrator to
         * intervene or wait till their session expires.
         *
         * @param maxSessionsPreventsLogin true to have an error at time of authentication, else false (default)
         * @return the {@link ConcurrencyControlConfigurer} for further customizations
         */
        public ConcurrencyControlConfigurer maxSessionsPreventsLogin(boolean maxSessionsPreventsLogin) {
            SessionManagementConfigurer.this.maxSessionsPreventsLogin = maxSessionsPreventsLogin;
            return this;
        }

        /**
         * Controls the {@link SessionRegistry} implementation used. The default
         * is {@link SessionRegistryImpl} which is an in memory implementation.
         *
         * @param sessionRegistry the {@link SessionRegistry} to use
         * @return the {@link ConcurrencyControlConfigurer} for further customizations
         */
        public ConcurrencyControlConfigurer sessionRegistry(SessionRegistry sessionRegistry) {
            SessionManagementConfigurer.this.sessionRegistry = sessionRegistry;
            return this;
        }

        /**
         * Used to chain back to the {@link SessionManagementConfigurer}
         *
         * @return the {@link SessionManagementConfigurer} for further customizations
         */
        public SessionManagementConfigurer<H> and() {
            return SessionManagementConfigurer.this;
        }

        private ConcurrencyControlConfigurer() {}
    }

    @Override
    public void init(H builder) throws Exception {
        SecurityContextRepository securityContextRepository = builder.getSharedObject(SecurityContextRepository.class);
        boolean stateless = isStateless();

        if(securityContextRepository == null) {
            if(stateless) {
                builder.setSharedObject(SecurityContextRepository.class, new NullSecurityContextRepository());
            } else {
                HttpSessionSecurityContextRepository httpSecurityRepository = new HttpSessionSecurityContextRepository();
                httpSecurityRepository.setDisableUrlRewriting(!enableSessionUrlRewriting);
                httpSecurityRepository.setAllowSessionCreation(isAllowSessionCreation());
                builder.setSharedObject(SecurityContextRepository.class, httpSecurityRepository);
            }
        }

        RequestCache requestCache = builder.getSharedObject(RequestCache.class);
        if(requestCache == null) {
            if(stateless) {
                builder.setSharedObject(RequestCache.class, new NullRequestCache());
            }
        }
        builder.setSharedObject(SessionAuthenticationStrategy.class, getSessionAuthenticationStrategy());
    }

    @Override
    public void configure(H http) throws Exception {
        SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
        SessionManagementFilter sessionManagementFilter = new SessionManagementFilter(securityContextRepository, getSessionAuthenticationStrategy());
        if(sessionAuthenticationErrorUrl != null) {
            sessionManagementFilter.setAuthenticationFailureHandler(new SimpleUrlAuthenticationFailureHandler(sessionAuthenticationErrorUrl));
        }
        if(invalidSessionUrl != null) {
            sessionManagementFilter.setInvalidSessionStrategy(new SimpleRedirectInvalidSessionStrategy(invalidSessionUrl));
        }
        sessionManagementFilter = postProcess(sessionManagementFilter);

        http.addFilter(sessionManagementFilter);
        if(isConcurrentSessionControlEnabled()) {
            ConcurrentSessionFilter concurrentSessionFilter = new ConcurrentSessionFilter(sessionRegistry, expiredUrl);
            concurrentSessionFilter = postProcess(concurrentSessionFilter);
            http.addFilter(concurrentSessionFilter);
        }
    }

    /**
     * Gets the {@link SessionCreationPolicy}. Can not be null.
     * @return the {@link SessionCreationPolicy}
     */
    SessionCreationPolicy getSessionCreationPolicy() {
        return sessionPolicy;
    }

    /**
     * Returns true if the {@link SessionCreationPolicy} allows session creation, else false
     * @return true if the {@link SessionCreationPolicy} allows session creation
     */
    private boolean isAllowSessionCreation() {
        return SessionCreationPolicy.ALWAYS == sessionPolicy || SessionCreationPolicy.IF_REQUIRED == sessionPolicy;
    }

    /**
     * Returns true if the {@link SessionCreationPolicy} is stateless
     * @return
     */
    private boolean isStateless() {
        return SessionCreationPolicy.STATELESS == sessionPolicy;
    }

    /**
     * Gets the customized {@link SessionAuthenticationStrategy} if
     * {@link #sessionAuthenticationStrategy(SessionAuthenticationStrategy)} was
     * specified. Otherwise creates a default
     * {@link SessionAuthenticationStrategy}.
     *
     * @return the {@link SessionAuthenticationStrategy} to use
     */
    private SessionAuthenticationStrategy getSessionAuthenticationStrategy() {
        if(sessionAuthenticationStrategy != null) {
            return sessionAuthenticationStrategy;
        }
        List<SessionAuthenticationStrategy> delegateStrategies = sessionAuthenticationStrategies;
        if(isConcurrentSessionControlEnabled()) {
            ConcurrentSessionControlAuthenticationStrategy concurrentSessionControlStrategy = new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry);
            concurrentSessionControlStrategy.setMaximumSessions(maximumSessions);
            concurrentSessionControlStrategy.setExceptionIfMaximumExceeded(maxSessionsPreventsLogin);
            concurrentSessionControlStrategy = postProcess(concurrentSessionControlStrategy);

            RegisterSessionAuthenticationStrategy registerSessionStrategy = new RegisterSessionAuthenticationStrategy(sessionRegistry);
            registerSessionStrategy = postProcess(registerSessionStrategy);

            delegateStrategies.addAll(Arrays.asList(concurrentSessionControlStrategy, sessionFixationAuthenticationStrategy, registerSessionStrategy));
        } else {
            delegateStrategies.add(sessionFixationAuthenticationStrategy);
        }
        sessionAuthenticationStrategy = postProcess(new CompositeSessionAuthenticationStrategy(delegateStrategies));
        return sessionAuthenticationStrategy;
    }

    /**
     * Returns true if the number of concurrent sessions per user should be restricted.
     * @return
     */
    private boolean isConcurrentSessionControlEnabled() {
        return maximumSessions != null;
    }

    /**
     * Creates the default {@link SessionAuthenticationStrategy} for session fixation
     * @return the default {@link SessionAuthenticationStrategy} for session fixation
     */
    private static SessionAuthenticationStrategy createDefaultSessionFixationProtectionStrategy() {
        try {
            return new ChangeSessionIdAuthenticationStrategy();
        } catch(IllegalStateException e) {
            return new SessionFixationProtectionStrategy();
        }
    }
}