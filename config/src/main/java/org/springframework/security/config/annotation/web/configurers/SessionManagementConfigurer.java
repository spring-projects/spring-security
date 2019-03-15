/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.GenericApplicationListenerAdapter;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
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
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.security.web.session.SimpleRedirectInvalidSessionStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;
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
 * <li>{@link ConcurrentSessionFilter} if there are restrictions on how many concurrent
 * sessions a user can have</li>
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
 * <li>{@link InvalidSessionStrategy}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * <ul>
 * <li>{@link SecurityContextRepository}</li>
 * <li>{@link AuthenticationTrustResolver} is optionally used to populate the
 * {@link HttpSessionSecurityContextRepository} and {@link SessionManagementFilter}</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 * @see SessionManagementFilter
 * @see ConcurrentSessionFilter
 */
public final class SessionManagementConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<SessionManagementConfigurer<H>, H> {
	private final SessionAuthenticationStrategy DEFAULT_SESSION_FIXATION_STRATEGY = createDefaultSessionFixationProtectionStrategy();
	private SessionAuthenticationStrategy sessionFixationAuthenticationStrategy = this.DEFAULT_SESSION_FIXATION_STRATEGY;
	private SessionAuthenticationStrategy sessionAuthenticationStrategy;
	private SessionAuthenticationStrategy providedSessionAuthenticationStrategy;
	private InvalidSessionStrategy invalidSessionStrategy;
	private SessionInformationExpiredStrategy expiredSessionStrategy;
	private List<SessionAuthenticationStrategy> sessionAuthenticationStrategies = new ArrayList<>();
	private SessionRegistry sessionRegistry;
	private Integer maximumSessions;
	private String expiredUrl;
	private boolean maxSessionsPreventsLogin;
	private SessionCreationPolicy sessionPolicy;
	private boolean enableSessionUrlRewriting;
	private String invalidSessionUrl;
	private String sessionAuthenticationErrorUrl;
	private AuthenticationFailureHandler sessionAuthenticationFailureHandler;

	/**
	 * Creates a new instance
	 * @see HttpSecurity#sessionManagement()
	 */
	public SessionManagementConfigurer() {
	}

	/**
	 * Setting this attribute will inject the {@link SessionManagementFilter} with a
	 * {@link SimpleRedirectInvalidSessionStrategy} configured with the attribute value.
	 * When an invalid session ID is submitted, the strategy will be invoked, redirecting
	 * to the configured URL.
	 *
	 * @param invalidSessionUrl the URL to redirect to when an invalid session is detected
	 * @return the {@link SessionManagementConfigurer} for further customization
	 */
	public SessionManagementConfigurer<H> invalidSessionUrl(String invalidSessionUrl) {
		this.invalidSessionUrl = invalidSessionUrl;
		return this;
	}

	/**
	 * Setting this attribute will inject the provided invalidSessionStrategy into the
	 * {@link SessionManagementFilter}. When an invalid session ID is submitted, the
	 * strategy will be invoked, redirecting to the configured URL.
	 * @param invalidSessionStrategy the strategy to use when an invalid session ID is
	 * submitted.
	 * @return the {@link SessionManagementConfigurer} for further customization
	 */
	public SessionManagementConfigurer<H> invalidSessionStrategy(
			InvalidSessionStrategy invalidSessionStrategy) {
		Assert.notNull(invalidSessionStrategy, "invalidSessionStrategy");
		this.invalidSessionStrategy = invalidSessionStrategy;
		return this;
	}

	/**
	 * Defines the URL of the error page which should be shown when the
	 * SessionAuthenticationStrategy raises an exception. If not set, an unauthorized
	 * (402) error code will be returned to the client. Note that this attribute doesn't
	 * apply if the error occurs during a form-based login, where the URL for
	 * authentication failure will take precedence.
	 *
	 * @param sessionAuthenticationErrorUrl the URL to redirect to
	 * @return the {@link SessionManagementConfigurer} for further customization
	 */
	public SessionManagementConfigurer<H> sessionAuthenticationErrorUrl(
			String sessionAuthenticationErrorUrl) {
		this.sessionAuthenticationErrorUrl = sessionAuthenticationErrorUrl;
		return this;
	}

	/**
	 * Defines the {@code AuthenticationFailureHandler} which will be used when the
	 * SessionAuthenticationStrategy raises an exception. If not set, an unauthorized
	 * (402) error code will be returned to the client. Note that this attribute doesn't
	 * apply if the error occurs during a form-based login, where the URL for
	 * authentication failure will take precedence.
	 *
	 * @param sessionAuthenticationFailureHandler the handler to use
	 * @return the {@link SessionManagementConfigurer} for further customization
	 */
	public SessionManagementConfigurer<H> sessionAuthenticationFailureHandler(
			AuthenticationFailureHandler sessionAuthenticationFailureHandler) {
		this.sessionAuthenticationFailureHandler = sessionAuthenticationFailureHandler;
		return this;
	}

	/**
	 * If set to true, allows HTTP sessions to be rewritten in the URLs when using
	 * {@link HttpServletResponse#encodeRedirectURL(String)} or
	 * {@link HttpServletResponse#encodeURL(String)}, otherwise disallows HTTP sessions to
	 * be included in the URL. This prevents leaking information to external domains.
	 *
	 * @param enableSessionUrlRewriting true if should allow the JSESSIONID to be
	 * rewritten into the URLs, else false (default)
	 * @return the {@link SessionManagementConfigurer} for further customization
	 * @see HttpSessionSecurityContextRepository#setDisableUrlRewriting(boolean)
	 */
	public SessionManagementConfigurer<H> enableSessionUrlRewriting(
			boolean enableSessionUrlRewriting) {
		this.enableSessionUrlRewriting = enableSessionUrlRewriting;
		return this;
	}

	/**
	 * Allows specifying the {@link SessionCreationPolicy}
	 * @param sessionCreationPolicy the {@link SessionCreationPolicy} to use. Cannot be
	 * null.
	 * @return the {@link SessionManagementConfigurer} for further customizations
	 * @see SessionCreationPolicy
	 * @throws IllegalArgumentException if {@link SessionCreationPolicy} is null.
	 */
	public SessionManagementConfigurer<H> sessionCreationPolicy(
			SessionCreationPolicy sessionCreationPolicy) {
		Assert.notNull(sessionCreationPolicy, "sessionCreationPolicy cannot be null");
		this.sessionPolicy = sessionCreationPolicy;
		return this;
	}

	/**
	 * Allows explicitly specifying the {@link SessionAuthenticationStrategy}.
	 * The default is to use {@link SessionFixationProtectionStrategy} for Servlet 3.1 or
	 * {@link ChangeSessionIdAuthenticationStrategy} for Servlet 3.1+.
	 * If restricting the maximum number of sessions is configured, then
	 * {@link CompositeSessionAuthenticationStrategy} delegating to
	 * {@link ConcurrentSessionControlAuthenticationStrategy},
	 * the default OR supplied {@code SessionAuthenticationStrategy} and
	 * {@link RegisterSessionAuthenticationStrategy}.
	 *
	 * <p>
	 * NOTE: Supplying a custom {@link SessionAuthenticationStrategy} will override the
	 * default session fixation strategy.
	 *
	 * @param sessionAuthenticationStrategy
	 * @return the {@link SessionManagementConfigurer} for further customizations
	 */
	public SessionManagementConfigurer<H> sessionAuthenticationStrategy(
			SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		this.providedSessionAuthenticationStrategy = sessionAuthenticationStrategy;
		return this;
	}

	/**
	 * Adds an additional {@link SessionAuthenticationStrategy} to be used within the
	 * {@link CompositeSessionAuthenticationStrategy}.
	 *
	 * @param sessionAuthenticationStrategy
	 * @return the {@link SessionManagementConfigurer} for further customizations
	 */
	SessionManagementConfigurer<H> addSessionAuthenticationStrategy(
			SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		this.sessionAuthenticationStrategies.add(sessionAuthenticationStrategy);
		return this;
	}

	public SessionFixationConfigurer sessionFixation() {
		return new SessionFixationConfigurer();
	}

	/**
	 * Controls the maximum number of sessions for a user. The default is to allow any
	 * number of users.
	 * @param maximumSessions the maximum number of sessions for a user
	 * @return the {@link SessionManagementConfigurer} for further customizations
	 */
	public ConcurrencyControlConfigurer maximumSessions(int maximumSessions) {
		this.maximumSessions = maximumSessions;
		return new ConcurrencyControlConfigurer();
	}

	/**
	 * Invokes {@link #postProcess(Object)} and sets the
	 * {@link SessionAuthenticationStrategy} for session fixation.
	 * @param sessionFixationAuthenticationStrategy
	 */
	private void setSessionFixationAuthenticationStrategy(
			SessionAuthenticationStrategy sessionFixationAuthenticationStrategy) {
		this.sessionFixationAuthenticationStrategy = postProcess(
				sessionFixationAuthenticationStrategy);
	}

	/**
	 * Allows configuring SessionFixation protection
	 *
	 * @author Rob Winch
	 */
	public final class SessionFixationConfigurer {
		/**
		 * Specifies that a new session should be created, but the session attributes from
		 * the original {@link HttpSession} should not be retained.
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
		 * Specifies that a new session should be created and the session attributes from
		 * the original {@link HttpSession} should be retained.
		 *
		 * @return the {@link SessionManagementConfigurer} for further customizations
		 */
		public SessionManagementConfigurer<H> migrateSession() {
			setSessionFixationAuthenticationStrategy(
					new SessionFixationProtectionStrategy());
			return SessionManagementConfigurer.this;
		}

		/**
		 * Specifies that the Servlet container-provided session fixation protection
		 * should be used. When a session authenticates, the Servlet 3.1 method
		 * {@code HttpServletRequest#changeSessionId()} is called to change the session ID
		 * and retain all session attributes. Using this option in a Servlet 3.0 or older
		 * container results in an {@link IllegalStateException}.
		 *
		 * @return the {@link SessionManagementConfigurer} for further customizations
		 * @throws IllegalStateException if the container is not Servlet 3.1 or newer.
		 */
		public SessionManagementConfigurer<H> changeSessionId() {
			setSessionFixationAuthenticationStrategy(
					new ChangeSessionIdAuthenticationStrategy());
			return SessionManagementConfigurer.this;
		}

		/**
		 * Specifies that no session fixation protection should be enabled. This may be
		 * useful when utilizing other mechanisms for protecting against session fixation.
		 * For example, if application container session fixation protection is already in
		 * use. Otherwise, this option is not recommended.
		 *
		 * @return the {@link SessionManagementConfigurer} for further customizations
		 */
		public SessionManagementConfigurer<H> none() {
			setSessionFixationAuthenticationStrategy(
					new NullAuthenticatedSessionStrategy());
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
		 * The URL to redirect to if a user tries to access a resource and their session
		 * has been expired due to too many sessions for the current user. The default is
		 * to write a simple error message to the response.
		 *
		 * @param expiredUrl the URL to redirect to
		 * @return the {@link ConcurrencyControlConfigurer} for further customizations
		 */
		public ConcurrencyControlConfigurer expiredUrl(String expiredUrl) {
			SessionManagementConfigurer.this.expiredUrl = expiredUrl;
			return this;
		}

		public ConcurrencyControlConfigurer expiredSessionStrategy(
				SessionInformationExpiredStrategy expiredSessionStrategy) {
			SessionManagementConfigurer.this.expiredSessionStrategy = expiredSessionStrategy;
			return this;
		}

		/**
		 * If true, prevents a user from authenticating when the
		 * {@link #maximumSessions(int)} has been reached. Otherwise (default), the user
		 * who authenticates is allowed access and an existing user's session is expired.
		 * The user's who's session is forcibly expired is sent to
		 * {@link #expiredUrl(String)}. The advantage of this approach is if a user
		 * accidentally does not log out, there is no need for an administrator to
		 * intervene or wait till their session expires.
		 *
		 * @param maxSessionsPreventsLogin true to have an error at time of
		 * authentication, else false (default)
		 * @return the {@link ConcurrencyControlConfigurer} for further customizations
		 */
		public ConcurrencyControlConfigurer maxSessionsPreventsLogin(
				boolean maxSessionsPreventsLogin) {
			SessionManagementConfigurer.this.maxSessionsPreventsLogin = maxSessionsPreventsLogin;
			return this;
		}

		/**
		 * Controls the {@link SessionRegistry} implementation used. The default is
		 * {@link SessionRegistryImpl} which is an in memory implementation.
		 *
		 * @param sessionRegistry the {@link SessionRegistry} to use
		 * @return the {@link ConcurrencyControlConfigurer} for further customizations
		 */
		public ConcurrencyControlConfigurer sessionRegistry(
				SessionRegistry sessionRegistry) {
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

		private ConcurrencyControlConfigurer() {
		}
	}

	@Override
	public void init(H http) throws Exception {
		SecurityContextRepository securityContextRepository = http
				.getSharedObject(SecurityContextRepository.class);
		boolean stateless = isStateless();

		if (securityContextRepository == null) {
			if (stateless) {
				http.setSharedObject(SecurityContextRepository.class,
						new NullSecurityContextRepository());
			}
			else {
				HttpSessionSecurityContextRepository httpSecurityRepository = new HttpSessionSecurityContextRepository();
				httpSecurityRepository
						.setDisableUrlRewriting(!this.enableSessionUrlRewriting);
				httpSecurityRepository.setAllowSessionCreation(isAllowSessionCreation());
				AuthenticationTrustResolver trustResolver = http
						.getSharedObject(AuthenticationTrustResolver.class);
				if (trustResolver != null) {
					httpSecurityRepository.setTrustResolver(trustResolver);
				}
				http.setSharedObject(SecurityContextRepository.class,
						httpSecurityRepository);
			}
		}

		RequestCache requestCache = http.getSharedObject(RequestCache.class);
		if (requestCache == null) {
			if (stateless) {
				http.setSharedObject(RequestCache.class, new NullRequestCache());
			}
		}
		http.setSharedObject(SessionAuthenticationStrategy.class,
				getSessionAuthenticationStrategy(http));
		http.setSharedObject(InvalidSessionStrategy.class, getInvalidSessionStrategy());
	}

	@Override
	public void configure(H http) throws Exception {
		SecurityContextRepository securityContextRepository = http
				.getSharedObject(SecurityContextRepository.class);
		SessionManagementFilter sessionManagementFilter = new SessionManagementFilter(
				securityContextRepository, getSessionAuthenticationStrategy(http));
		if (this.sessionAuthenticationErrorUrl != null) {
			sessionManagementFilter.setAuthenticationFailureHandler(
					new SimpleUrlAuthenticationFailureHandler(
							this.sessionAuthenticationErrorUrl));
		}
		InvalidSessionStrategy strategy = getInvalidSessionStrategy();
		if (strategy != null) {
			sessionManagementFilter.setInvalidSessionStrategy(strategy);
		}
		AuthenticationFailureHandler failureHandler = getSessionAuthenticationFailureHandler();
		if (failureHandler != null) {
			sessionManagementFilter.setAuthenticationFailureHandler(failureHandler);
		}
		AuthenticationTrustResolver trustResolver = http
				.getSharedObject(AuthenticationTrustResolver.class);
		if (trustResolver != null) {
			sessionManagementFilter.setTrustResolver(trustResolver);
		}
		sessionManagementFilter = postProcess(sessionManagementFilter);

		http.addFilter(sessionManagementFilter);
		if (isConcurrentSessionControlEnabled()) {
			ConcurrentSessionFilter concurrentSessionFilter = createConccurencyFilter(http);

			concurrentSessionFilter = postProcess(concurrentSessionFilter);
			http.addFilter(concurrentSessionFilter);
		}
	}

	private ConcurrentSessionFilter createConccurencyFilter(H http) {
		SessionInformationExpiredStrategy expireStrategy = getExpiredSessionStrategy();
		SessionRegistry sessionRegistry = getSessionRegistry(http);
		if (expireStrategy == null) {
			return new ConcurrentSessionFilter(sessionRegistry);
		}

		return new ConcurrentSessionFilter(sessionRegistry, expireStrategy);
	}

	/**
	 * Gets the {@link InvalidSessionStrategy} to use. If null and
	 * {@link #invalidSessionUrl} is not null defaults to
	 * {@link SimpleRedirectInvalidSessionStrategy}.
	 *
	 * @return the {@link InvalidSessionStrategy} to use
	 */
	InvalidSessionStrategy getInvalidSessionStrategy() {
		if (this.invalidSessionStrategy != null) {
			return this.invalidSessionStrategy;
		}
		if (this.invalidSessionUrl != null) {
			this.invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
					this.invalidSessionUrl);
		}
		if (this.invalidSessionUrl == null) {
			return null;
		}
		if (this.invalidSessionStrategy == null) {
			this.invalidSessionStrategy = new SimpleRedirectInvalidSessionStrategy(
					this.invalidSessionUrl);
		}
		return this.invalidSessionStrategy;
	}

	SessionInformationExpiredStrategy getExpiredSessionStrategy() {
		if (this.expiredSessionStrategy != null) {
			return this.expiredSessionStrategy;
		}

		if (this.expiredUrl == null) {
			return null;
		}

		if (this.expiredSessionStrategy == null) {
			this.expiredSessionStrategy = new SimpleRedirectSessionInformationExpiredStrategy(
					this.expiredUrl);
		}
		return this.expiredSessionStrategy;
	}

	AuthenticationFailureHandler getSessionAuthenticationFailureHandler() {
		if (this.sessionAuthenticationFailureHandler != null) {
			return this.sessionAuthenticationFailureHandler;
		}

		if (this.sessionAuthenticationErrorUrl == null) {
			return null;
		}

		if (this.sessionAuthenticationFailureHandler == null) {
			this.sessionAuthenticationFailureHandler = new SimpleUrlAuthenticationFailureHandler(
					this.sessionAuthenticationErrorUrl);
		}
		return this.sessionAuthenticationFailureHandler;
	}

	/**
	 * Gets the {@link SessionCreationPolicy}. Can not be null.
	 * @return the {@link SessionCreationPolicy}
	 */
	SessionCreationPolicy getSessionCreationPolicy() {
		if (this.sessionPolicy != null) {
			return this.sessionPolicy;
		}

		SessionCreationPolicy sessionPolicy =
				getBuilder().getSharedObject(SessionCreationPolicy.class);
		return sessionPolicy == null ?
				SessionCreationPolicy.IF_REQUIRED : sessionPolicy;
	}

	/**
	 * Returns true if the {@link SessionCreationPolicy} allows session creation, else
	 * false
	 * @return true if the {@link SessionCreationPolicy} allows session creation
	 */
	private boolean isAllowSessionCreation() {
		SessionCreationPolicy sessionPolicy = getSessionCreationPolicy();
		return SessionCreationPolicy.ALWAYS == sessionPolicy
				|| SessionCreationPolicy.IF_REQUIRED == sessionPolicy;
	}

	/**
	 * Returns true if the {@link SessionCreationPolicy} is stateless
	 * @return
	 */
	private boolean isStateless() {
		SessionCreationPolicy sessionPolicy = getSessionCreationPolicy();
		return SessionCreationPolicy.STATELESS == sessionPolicy;
	}

	/**
	 * Gets the customized {@link SessionAuthenticationStrategy} if
	 * {@link #sessionAuthenticationStrategy(SessionAuthenticationStrategy)} was
	 * specified. Otherwise creates a default {@link SessionAuthenticationStrategy}.
	 *
	 * @return the {@link SessionAuthenticationStrategy} to use
	 */
	private SessionAuthenticationStrategy getSessionAuthenticationStrategy(H http) {
		if (this.sessionAuthenticationStrategy != null) {
			return this.sessionAuthenticationStrategy;
		}
		List<SessionAuthenticationStrategy> delegateStrategies = this.sessionAuthenticationStrategies;
		SessionAuthenticationStrategy defaultSessionAuthenticationStrategy;
		if (this.providedSessionAuthenticationStrategy == null) {
			// If the user did not provide a SessionAuthenticationStrategy
			// then default to sessionFixationAuthenticationStrategy
			defaultSessionAuthenticationStrategy = postProcess(
					this.sessionFixationAuthenticationStrategy);
		}
		else {
			defaultSessionAuthenticationStrategy = this.providedSessionAuthenticationStrategy;
		}
		if (isConcurrentSessionControlEnabled()) {
			SessionRegistry sessionRegistry = getSessionRegistry(http);
			ConcurrentSessionControlAuthenticationStrategy concurrentSessionControlStrategy = new ConcurrentSessionControlAuthenticationStrategy(
					sessionRegistry);
			concurrentSessionControlStrategy.setMaximumSessions(this.maximumSessions);
			concurrentSessionControlStrategy
					.setExceptionIfMaximumExceeded(this.maxSessionsPreventsLogin);
			concurrentSessionControlStrategy = postProcess(
					concurrentSessionControlStrategy);

			RegisterSessionAuthenticationStrategy registerSessionStrategy = new RegisterSessionAuthenticationStrategy(
					sessionRegistry);
			registerSessionStrategy = postProcess(registerSessionStrategy);

			delegateStrategies.addAll(Arrays.asList(concurrentSessionControlStrategy,
					defaultSessionAuthenticationStrategy, registerSessionStrategy));
		}
		else {
			delegateStrategies.add(defaultSessionAuthenticationStrategy);
		}
		this.sessionAuthenticationStrategy = postProcess(
				new CompositeSessionAuthenticationStrategy(delegateStrategies));
		return this.sessionAuthenticationStrategy;
	}

	private SessionRegistry getSessionRegistry(H http) {
		if (this.sessionRegistry == null) {
			SessionRegistryImpl sessionRegistry = new SessionRegistryImpl();
			registerDelegateApplicationListener(http, sessionRegistry);
			this.sessionRegistry = sessionRegistry;
		}
		return this.sessionRegistry;
	}

	private void registerDelegateApplicationListener(H http,
			ApplicationListener<?> delegate) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		if (context == null) {
			return;
		}
		if (context.getBeansOfType(DelegatingApplicationListener.class).isEmpty()) {
			return;
		}
		DelegatingApplicationListener delegating = context
				.getBean(DelegatingApplicationListener.class);
		SmartApplicationListener smartListener = new GenericApplicationListenerAdapter(
				delegate);
		delegating.addListener(smartListener);
	}

	/**
	 * Returns true if the number of concurrent sessions per user should be restricted.
	 * @return
	 */
	private boolean isConcurrentSessionControlEnabled() {
		return this.maximumSessions != null;
	}

	/**
	 * Creates the default {@link SessionAuthenticationStrategy} for session fixation
	 * @return the default {@link SessionAuthenticationStrategy} for session fixation
	 */
	private static SessionAuthenticationStrategy createDefaultSessionFixationProtectionStrategy() {
		try {
			return new ChangeSessionIdAuthenticationStrategy();
		}
		catch (IllegalStateException e) {
			return new SessionFixationProtectionStrategy();
		}
	}
}
