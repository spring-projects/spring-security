/*
 * Copyright 2002-2025 the original author or authors.
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.function.Supplier;

import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.CompositeAccessDeniedHandler;
import org.springframework.security.web.access.DelegatingAccessDeniedHandler;
import org.springframework.security.web.access.ObservationMarkingAccessDeniedHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.session.InvalidSessionAccessDeniedHandler;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Adds
 * <a href="https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)" >CSRF</a>
 * protection for the methods as specified by
 * {@link #requireCsrfProtectionMatcher(RequestMatcher)}.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link CsrfFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared objects are created.
 *
 * <h2>Shared Objects Used</h2>
 *
 * <ul>
 * <li>{@link ExceptionHandlingConfigurer#accessDeniedHandler(AccessDeniedHandler)} is
 * used to determine how to handle CSRF attempts</li>
 * <li>{@link InvalidSessionStrategy}</li>
 * </ul>
 *
 * @author Rob Winch
 * @author Michael Vitz
 * @since 3.2
 */
public final class CsrfConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<CsrfConfigurer<H>, H> {

	private CsrfTokenRepository csrfTokenRepository = new HttpSessionCsrfTokenRepository();

	private RequestMatcher requireCsrfProtectionMatcher = CsrfFilter.DEFAULT_CSRF_MATCHER;

	private List<RequestMatcher> ignoredCsrfProtectionMatchers = new ArrayList<>();

	private SessionAuthenticationStrategy sessionAuthenticationStrategy;

	private CsrfTokenRequestHandler requestHandler;

	private final ApplicationContext context;

	/**
	 * Creates a new instance
	 * @see HttpSecurity#csrf()
	 */
	public CsrfConfigurer(ApplicationContext context) {
		this.context = context;
	}

	/**
	 * Specify the {@link CsrfTokenRepository} to use. The default is an
	 * {@link HttpSessionCsrfTokenRepository}.
	 * @param csrfTokenRepository the {@link CsrfTokenRepository} to use
	 * @return the {@link CsrfConfigurer} for further customizations
	 */
	public CsrfConfigurer<H> csrfTokenRepository(CsrfTokenRepository csrfTokenRepository) {
		Assert.notNull(csrfTokenRepository, "csrfTokenRepository cannot be null");
		this.csrfTokenRepository = csrfTokenRepository;
		return this;
	}

	/**
	 * Specify the {@link RequestMatcher} to use for determining when CSRF should be
	 * applied. The default is to ignore GET, HEAD, TRACE, OPTIONS and process all other
	 * requests.
	 * @param requireCsrfProtectionMatcher the {@link RequestMatcher} to use
	 * @return the {@link CsrfConfigurer} for further customizations
	 */
	public CsrfConfigurer<H> requireCsrfProtectionMatcher(RequestMatcher requireCsrfProtectionMatcher) {
		Assert.notNull(requireCsrfProtectionMatcher, "requireCsrfProtectionMatcher cannot be null");
		this.requireCsrfProtectionMatcher = requireCsrfProtectionMatcher;
		return this;
	}

	/**
	 * Specify a {@link CsrfTokenRequestHandler} to use for making the {@code CsrfToken}
	 * available as a request attribute.
	 * @param requestHandler the {@link CsrfTokenRequestHandler} to use
	 * @return the {@link CsrfConfigurer} for further customizations
	 * @since 5.8
	 */
	public CsrfConfigurer<H> csrfTokenRequestHandler(CsrfTokenRequestHandler requestHandler) {
		this.requestHandler = requestHandler;
		return this;
	}

	/**
	 * <p>
	 * Allows specifying {@link HttpServletRequest}s that should not use CSRF Protection
	 * even if they match the {@link #requireCsrfProtectionMatcher(RequestMatcher)}.
	 * </p>
	 *
	 * <p>
	 * For example, the following configuration will ensure CSRF protection ignores:
	 * </p>
	 * <ul>
	 * <li>Any GET, HEAD, TRACE, OPTIONS (this is the default)</li>
	 * <li>We also explicitly state to ignore any request that has a "X-Requested-With:
	 * XMLHttpRequest" header</li>
	 * </ul>
	 *
	 * <pre>
	 * http
	 *     .csrf()
	 *         .ignoringRequestMatchers((request) -&gt; "XMLHttpRequest".equals(request.getHeader("X-Requested-With")))
	 *         .and()
	 *     ...
	 * </pre>
	 *
	 * @since 5.1
	 */
	public CsrfConfigurer<H> ignoringRequestMatchers(RequestMatcher... requestMatchers) {
		return new IgnoreCsrfProtectionRegistry(this.context).requestMatchers(requestMatchers).and();
	}

	/**
	 * <p>
	 * Allows specifying {@link HttpServletRequest} that should not use CSRF Protection
	 * even if they match the {@link #requireCsrfProtectionMatcher(RequestMatcher)}.
	 * </p>
	 *
	 * <p>
	 * For example, the following configuration will ensure CSRF protection ignores:
	 * </p>
	 * <ul>
	 * <li>Any GET, HEAD, TRACE, OPTIONS (this is the default)</li>
	 * <li>We also explicitly state to ignore any request that starts with "/sockjs/"</li>
	 * </ul>
	 *
	 * <pre>
	 * http
	 *     .csrf()
	 *         .ignoringRequestMatchers("/sockjs/**")
	 *         .and()
	 *     ...
	 * </pre>
	 *
	 * @since 5.8
	 * @see AbstractRequestMatcherRegistry#requestMatchers(String...)
	 */
	public CsrfConfigurer<H> ignoringRequestMatchers(String... patterns) {
		return new IgnoreCsrfProtectionRegistry(this.context).requestMatchers(patterns).and();
	}

	/**
	 * <p>
	 * Specify the {@link SessionAuthenticationStrategy} to use. The default is a
	 * {@link CsrfAuthenticationStrategy}.
	 * </p>
	 * @param sessionAuthenticationStrategy the {@link SessionAuthenticationStrategy} to
	 * use
	 * @return the {@link CsrfConfigurer} for further customizations
	 * @since 5.2
	 */
	public CsrfConfigurer<H> sessionAuthenticationStrategy(
			SessionAuthenticationStrategy sessionAuthenticationStrategy) {
		Assert.notNull(sessionAuthenticationStrategy, "sessionAuthenticationStrategy cannot be null");
		this.sessionAuthenticationStrategy = sessionAuthenticationStrategy;
		return this;
	}

	/**
	 * <p>
	 * Sensible CSRF defaults when used in combination with a single page application.
	 * Creates a cookie-based token repository and a custom request handler to resolve the
	 * actual token value instead of the encoded token.
	 * </p>
	 * @return the {@link CsrfConfigurer} for further customizations
	 * @since 7.0
	 */
	public CsrfConfigurer<H> spa() {
		this.csrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
		this.requestHandler = new SpaCsrfTokenRequestHandler();
		return this;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void configure(H http) {
		CsrfFilter filter = new CsrfFilter(this.csrfTokenRepository);
		RequestMatcher requireCsrfProtectionMatcher = getRequireCsrfProtectionMatcher();
		if (requireCsrfProtectionMatcher != null) {
			filter.setRequireCsrfProtectionMatcher(requireCsrfProtectionMatcher);
		}
		AccessDeniedHandler accessDeniedHandler = createAccessDeniedHandler(http);
		ObservationRegistry registry = getObservationRegistry();
		if (!registry.isNoop()) {
			ObservationMarkingAccessDeniedHandler observable = new ObservationMarkingAccessDeniedHandler(registry);
			accessDeniedHandler = new CompositeAccessDeniedHandler(observable, accessDeniedHandler);
		}
		if (accessDeniedHandler != null) {
			filter.setAccessDeniedHandler(accessDeniedHandler);
		}
		LogoutConfigurer<H> logoutConfigurer = http.getConfigurer(LogoutConfigurer.class);
		if (logoutConfigurer != null) {
			logoutConfigurer.addLogoutHandler(new CsrfLogoutHandler(this.csrfTokenRepository));
		}
		SessionManagementConfigurer<H> sessionConfigurer = http.getConfigurer(SessionManagementConfigurer.class);
		if (sessionConfigurer != null) {
			sessionConfigurer.addSessionAuthenticationStrategy(getSessionAuthenticationStrategy());
		}
		if (this.requestHandler != null) {
			filter.setRequestHandler(this.requestHandler);
		}
		filter = postProcess(filter);
		http.addFilter(filter);
	}

	/**
	 * Gets the final {@link RequestMatcher} to use by combining the
	 * {@link #requireCsrfProtectionMatcher(RequestMatcher)} and any {@link #ignore()}.
	 * @return the {@link RequestMatcher} to use
	 */
	private RequestMatcher getRequireCsrfProtectionMatcher() {
		if (this.ignoredCsrfProtectionMatchers.isEmpty()) {
			return this.requireCsrfProtectionMatcher;
		}
		return new AndRequestMatcher(this.requireCsrfProtectionMatcher,
				new NegatedRequestMatcher(new OrRequestMatcher(this.ignoredCsrfProtectionMatchers)));
	}

	/**
	 * Gets the default {@link AccessDeniedHandler} from the
	 * {@link ExceptionHandlingConfigurer#getAccessDeniedHandler(HttpSecurityBuilder)} or
	 * create a {@link AccessDeniedHandlerImpl} if not available.
	 * @param http the {@link HttpSecurityBuilder}
	 * @return the {@link AccessDeniedHandler}
	 */
	@SuppressWarnings("unchecked")
	private AccessDeniedHandler getDefaultAccessDeniedHandler(H http) {
		ExceptionHandlingConfigurer<H> exceptionConfig = http.getConfigurer(ExceptionHandlingConfigurer.class);
		AccessDeniedHandler handler = null;
		if (exceptionConfig != null) {
			handler = exceptionConfig.getAccessDeniedHandler(http);
		}
		if (handler == null) {
			handler = new AccessDeniedHandlerImpl();
		}
		return handler;
	}

	/**
	 * Gets the default {@link InvalidSessionStrategy} from the
	 * {@link SessionManagementConfigurer#getInvalidSessionStrategy()} or null if not
	 * available.
	 * @param http the {@link HttpSecurityBuilder}
	 * @return the {@link InvalidSessionStrategy}
	 */
	@SuppressWarnings("unchecked")
	private InvalidSessionStrategy getInvalidSessionStrategy(H http) {
		SessionManagementConfigurer<H> sessionManagement = http.getConfigurer(SessionManagementConfigurer.class);
		if (sessionManagement == null) {
			return null;
		}
		return sessionManagement.getInvalidSessionStrategy();
	}

	/**
	 * Creates the {@link AccessDeniedHandler} from the result of
	 * {@link #getDefaultAccessDeniedHandler(HttpSecurityBuilder)} and
	 * {@link #getInvalidSessionStrategy(HttpSecurityBuilder)}. If
	 * {@link #getInvalidSessionStrategy(HttpSecurityBuilder)} is non-null, then a
	 * {@link DelegatingAccessDeniedHandler} is used in combination with
	 * {@link InvalidSessionAccessDeniedHandler} and the
	 * {@link #getDefaultAccessDeniedHandler(HttpSecurityBuilder)}. Otherwise, only
	 * {@link #getDefaultAccessDeniedHandler(HttpSecurityBuilder)} is used.
	 * @param http the {@link HttpSecurityBuilder}
	 * @return the {@link AccessDeniedHandler}
	 */
	private AccessDeniedHandler createAccessDeniedHandler(H http) {
		InvalidSessionStrategy invalidSessionStrategy = getInvalidSessionStrategy(http);
		AccessDeniedHandler defaultAccessDeniedHandler = getDefaultAccessDeniedHandler(http);
		if (invalidSessionStrategy == null) {
			return defaultAccessDeniedHandler;
		}
		InvalidSessionAccessDeniedHandler invalidSessionDeniedHandler = new InvalidSessionAccessDeniedHandler(
				invalidSessionStrategy);
		LinkedHashMap<Class<? extends AccessDeniedException>, AccessDeniedHandler> handlers = new LinkedHashMap<>();
		handlers.put(MissingCsrfTokenException.class, invalidSessionDeniedHandler);
		return new DelegatingAccessDeniedHandler(handlers, defaultAccessDeniedHandler);
	}

	/**
	 * Gets the {@link SessionAuthenticationStrategy} to use. If none was set by the user
	 * a {@link CsrfAuthenticationStrategy} is created.
	 * @return the {@link SessionAuthenticationStrategy}
	 * @since 5.2
	 */
	private SessionAuthenticationStrategy getSessionAuthenticationStrategy() {
		if (this.sessionAuthenticationStrategy != null) {
			return this.sessionAuthenticationStrategy;
		}
		CsrfAuthenticationStrategy csrfAuthenticationStrategy = new CsrfAuthenticationStrategy(
				this.csrfTokenRepository);
		if (this.requestHandler != null) {
			csrfAuthenticationStrategy.setRequestHandler(this.requestHandler);
		}
		return csrfAuthenticationStrategy;
	}

	private ObservationRegistry getObservationRegistry() {
		ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(ObservationRegistry.class);
		if (names.length == 1) {
			return context.getBean(ObservationRegistry.class);
		}
		else {
			return ObservationRegistry.NOOP;
		}
	}

	/**
	 * Allows registering {@link RequestMatcher} instances that should be ignored (even if
	 * the {@link HttpServletRequest} matches the
	 * {@link CsrfConfigurer#requireCsrfProtectionMatcher(RequestMatcher)}.
	 *
	 * @author Rob Winch
	 * @since 4.0
	 */
	private class IgnoreCsrfProtectionRegistry extends AbstractRequestMatcherRegistry<IgnoreCsrfProtectionRegistry> {

		IgnoreCsrfProtectionRegistry(ApplicationContext context) {
			setApplicationContext(context);
		}

		CsrfConfigurer<H> and() {
			return CsrfConfigurer.this;
		}

		@Override
		protected IgnoreCsrfProtectionRegistry chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			CsrfConfigurer.this.ignoredCsrfProtectionMatchers.addAll(requestMatchers);
			return this;
		}

	}

	private static final class SpaCsrfTokenRequestHandler implements CsrfTokenRequestHandler {

		private final CsrfTokenRequestAttributeHandler plain = new CsrfTokenRequestAttributeHandler();

		private final CsrfTokenRequestAttributeHandler xor = new XorCsrfTokenRequestAttributeHandler();

		SpaCsrfTokenRequestHandler() {
			this.xor.setCsrfRequestAttributeName(null);
		}

		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response, Supplier<CsrfToken> csrfToken) {
			this.xor.handle(request, response, csrfToken);
		}

		@Override
		public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
			String headerValue = request.getHeader(csrfToken.getHeaderName());
			return (StringUtils.hasText(headerValue) ? this.plain : this.xor).resolveCsrfTokenValue(request, csrfToken);
		}

	}

}
