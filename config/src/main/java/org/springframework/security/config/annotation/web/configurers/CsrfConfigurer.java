/*
 * Copyright 2002-2019 the original author or authors.
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

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.DelegatingAccessDeniedHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.LazyCsrfTokenRepository;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.session.InvalidSessionAccessDeniedHandler;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

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

	private CsrfTokenRepository csrfTokenRepository = new LazyCsrfTokenRepository(new HttpSessionCsrfTokenRepository());

	private RequestMatcher requireCsrfProtectionMatcher = CsrfFilter.DEFAULT_CSRF_MATCHER;

	private List<RequestMatcher> ignoredCsrfProtectionMatchers = new ArrayList<>();

	private SessionAuthenticationStrategy sessionAuthenticationStrategy;

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
	 * {@link HttpSessionCsrfTokenRepository} wrapped by {@link LazyCsrfTokenRepository}.
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
	 *         .ignoringAntMatchers("/sockjs/**")
	 *         .and()
	 *     ...
	 * </pre>
	 *
	 * @since 4.0
	 */
	public CsrfConfigurer<H> ignoringAntMatchers(String... antPatterns) {
		return new IgnoreCsrfProtectionRegistry(this.context).antMatchers(antPatterns).and();
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
	 *         .ignoringRequestMatchers(request -> "XMLHttpRequest".equals(request.getHeader("X-Requested-With")))
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

	@SuppressWarnings("unchecked")
	@Override
	public void configure(H http) {
		CsrfFilter filter = new CsrfFilter(this.csrfTokenRepository);
		RequestMatcher requireCsrfProtectionMatcher = getRequireCsrfProtectionMatcher();
		if (requireCsrfProtectionMatcher != null) {
			filter.setRequireCsrfProtectionMatcher(requireCsrfProtectionMatcher);
		}
		AccessDeniedHandler accessDeniedHandler = createAccessDeniedHandler(http);
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
	 * {@link ExceptionHandlingConfigurer#getAccessDeniedHandler()} or create a
	 * {@link AccessDeniedHandlerImpl} if not available.
	 * @param http the {@link HttpSecurityBuilder}
	 * @return the {@link AccessDeniedHandler}
	 */
	@SuppressWarnings("unchecked")
	private AccessDeniedHandler getDefaultAccessDeniedHandler(H http) {
		ExceptionHandlingConfigurer<H> exceptionConfig = http.getConfigurer(ExceptionHandlingConfigurer.class);
		AccessDeniedHandler handler = null;
		if (exceptionConfig != null) {
			handler = exceptionConfig.getAccessDeniedHandler();
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
		else {
			return new CsrfAuthenticationStrategy(this.csrfTokenRepository);
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

		@Override
		public MvcMatchersIgnoreCsrfProtectionRegistry mvcMatchers(HttpMethod method, String... mvcPatterns) {
			List<MvcRequestMatcher> mvcMatchers = createMvcMatchers(method, mvcPatterns);
			CsrfConfigurer.this.ignoredCsrfProtectionMatchers.addAll(mvcMatchers);
			return new MvcMatchersIgnoreCsrfProtectionRegistry(getApplicationContext(), mvcMatchers);
		}

		@Override
		public MvcMatchersIgnoreCsrfProtectionRegistry mvcMatchers(String... mvcPatterns) {
			return mvcMatchers(null, mvcPatterns);
		}

		public CsrfConfigurer<H> and() {
			return CsrfConfigurer.this;
		}

		@Override
		protected IgnoreCsrfProtectionRegistry chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			CsrfConfigurer.this.ignoredCsrfProtectionMatchers.addAll(requestMatchers);
			return this;
		}

	}

	/**
	 * An {@link IgnoreCsrfProtectionRegistry} that allows optionally configuring the
	 * {@link MvcRequestMatcher#setMethod(HttpMethod)}
	 *
	 * @author Rob Winch
	 */
	private final class MvcMatchersIgnoreCsrfProtectionRegistry extends IgnoreCsrfProtectionRegistry {

		private final List<MvcRequestMatcher> mvcMatchers;

		private MvcMatchersIgnoreCsrfProtectionRegistry(ApplicationContext context,
				List<MvcRequestMatcher> mvcMatchers) {
			super(context);
			this.mvcMatchers = mvcMatchers;
		}

		public IgnoreCsrfProtectionRegistry servletPath(String servletPath) {
			for (MvcRequestMatcher matcher : this.mvcMatchers) {
				matcher.setServletPath(servletPath);
			}
			return this;
		}

	}

}
