/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.saml2;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.core.Version;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml3LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml3LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlLogoutRequestHandler;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlLogoutResponseHandler;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestSuccessHandler;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseSuccessHandler;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Adds SAML 2.0 logout support.
 *
 * <h2>Security Filters</h2>
 *
 * The following Filters are populated
 *
 * <ul>
 * <li>{@link LogoutFilter}</li>
 * <li>{@link Saml2LogoutRequestFilter}</li>
 * <li>{@link Saml2LogoutResponseFilter}</li>
 * </ul>
 *
 * <p>
 * The following configuration options are available:
 *
 * <ul>
 * <li>{@link #logoutUrl} - The URL to initiate SAML 2.0 Logout</li>
 * <li>{@link #logoutRequestMatcher} - The {@link RequestMatcher} to initiate SAML 2.0
 * Logout</li>
 * <li>{@link #logoutSuccessHandler} - The {@link LogoutSuccessHandler} to execute once
 * SAML 2.0 Logout is complete</li>
 * <li>{@link LogoutRequestConfigurer#logoutRequestMatcher} - The {@link RequestMatcher}
 * to receive SAML 2.0 Logout Requests</li>
 * <li>{@link LogoutRequestConfigurer#logoutHandler} - The {@link LogoutHandler} for
 * processing SAML 2.0 Logout Requests</li>
 * <li>{@link LogoutRequestConfigurer#logoutRequestResolver} - The
 * {@link Saml2LogoutRequestResolver} for creating SAML 2.0 Logout Requests</li>
 * <li>{@link LogoutRequestConfigurer#logoutRequestRepository} - The
 * {@link Saml2LogoutRequestRepository} for storing SAML 2.0 Logout Requests</li>
 * <li>{@link LogoutResponseConfigurer#logoutRequestMatcher} - The {@link RequestMatcher}
 * to receive SAML 2.0 Logout Responses</li>
 * <li>{@link LogoutResponseConfigurer#logoutHandler} - The {@link LogoutHandler} for
 * processing SAML 2.0 Logout Responses</li>
 * <li>{@link LogoutResponseConfigurer#logoutResponseResolver} - The
 * {@link Saml2LogoutResponseResolver} for creating SAML 2.0 Logout Responses</li>
 * </ul>
 *
 * <h2>Shared Objects Created</h2>
 *
 * No shared Objects are created
 *
 * <h2>Shared Objects Used</h2>
 *
 * Uses {@link CsrfTokenRepository} to add the {@link CsrfLogoutHandler}.
 *
 * @author Josh Cummings
 * @since 5.5
 * @see Saml2LogoutConfigurer
 */
public final class Saml2LogoutConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<Saml2LogoutConfigurer<H>, H> {

	private ApplicationContext context;

	private List<LogoutHandler> logoutHandlers = new ArrayList<>();

	private SecurityContextLogoutHandler contextLogoutHandler = new SecurityContextLogoutHandler();

	private String logoutSuccessUrl = "/login?logout";

	private LogoutSuccessHandler logoutSuccessHandler;

	private String logoutUrl = "/logout";

	private RequestMatcher logoutRequestMatcher;

	private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

	private LogoutRequestConfigurer logoutRequestConfigurer;

	private LogoutResponseConfigurer logoutResponseConfigurer;

	/**
	 * Creates a new instance
	 * @see HttpSecurity#logout()
	 */
	public Saml2LogoutConfigurer(ApplicationContext context) {
		this.context = context;
		this.logoutRequestConfigurer = new LogoutRequestConfigurer();
		this.logoutResponseConfigurer = new LogoutResponseConfigurer(this.logoutRequestConfigurer);
	}

	/**
	 * Adds a {@link LogoutHandler}. {@link SecurityContextLogoutHandler} and
	 * {@link LogoutSuccessEventPublishingLogoutHandler} are added as last
	 * {@link LogoutHandler} instances by default.
	 * @param logoutHandler the {@link LogoutHandler} to add
	 * @return the {@link Saml2LogoutConfigurer} for further customization
	 */
	public Saml2LogoutConfigurer<H> addLogoutHandler(LogoutHandler logoutHandler) {
		Assert.notNull(logoutHandler, "logoutHandler cannot be null");
		this.logoutHandlers.add(logoutHandler);
		return this;
	}

	/**
	 * Specifies if {@link SecurityContextLogoutHandler} should clear the
	 * {@link Authentication} at the time of logout.
	 * @param clearAuthentication true {@link SecurityContextLogoutHandler} should clear
	 * the {@link Authentication} (default), or false otherwise.
	 * @return the {@link Saml2LogoutConfigurer} for further customization
	 */
	public Saml2LogoutConfigurer<H> clearAuthentication(boolean clearAuthentication) {
		this.contextLogoutHandler.setClearAuthentication(clearAuthentication);
		return this;
	}

	/**
	 * Configures {@link SecurityContextLogoutHandler} to invalidate the
	 * {@link HttpSession} at the time of logout.
	 * @param invalidateHttpSession true if the {@link HttpSession} should be invalidated
	 * (default), or false otherwise.
	 * @return the {@link Saml2LogoutConfigurer} for further customization
	 */
	public Saml2LogoutConfigurer<H> invalidateHttpSession(boolean invalidateHttpSession) {
		this.contextLogoutHandler.setInvalidateHttpSession(invalidateHttpSession);
		return this;
	}

	/**
	 * The URL that triggers log out to occur (default is "/logout"). If CSRF protection
	 * is enabled (default), then the request must also be a POST. This means that by
	 * default POST "/logout" is required to trigger a log out. If CSRF protection is
	 * disabled, then any HTTP method is allowed.
	 *
	 * <p>
	 * It is considered best practice to use an HTTP POST on any action that changes state
	 * (i.e. log out) to protect against
	 * <a href="https://en.wikipedia.org/wiki/Cross-site_request_forgery">CSRF
	 * attacks</a>. If you really want to use an HTTP GET, you can use
	 * <code>logoutRequestMatcher(new AntPathRequestMatcher(logoutUrl, "GET"));</code>
	 * </p>
	 * @param logoutUrl the URL that will invoke logout.
	 * @return the {@link Saml2LogoutConfigurer} for further customization
	 * @see #logoutRequestMatcher(RequestMatcher)
	 * @see HttpSecurity#csrf()
	 */
	public Saml2LogoutConfigurer<H> logoutUrl(String logoutUrl) {
		this.logoutRequestMatcher = null;
		this.logoutUrl = logoutUrl;
		return this;
	}

	/**
	 * The RequestMatcher that triggers log out to occur. In most circumstances users will
	 * use {@link #logoutUrl(String)} which helps enforce good practices.
	 * @param logoutRequestMatcher the RequestMatcher used to determine if logout should
	 * occur.
	 * @return the {@link Saml2LogoutConfigurer} for further customization
	 * @see #logoutUrl(String)
	 */
	public Saml2LogoutConfigurer<H> logoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		this.logoutUrl = null;
		this.logoutRequestMatcher = logoutRequestMatcher;
		return this;
	}

	/**
	 * The URL to redirect to after logout has occurred. The default is "/login?logout".
	 * This is a shortcut for invoking {@link #logoutSuccessHandler(LogoutSuccessHandler)}
	 * with a {@link SimpleUrlLogoutSuccessHandler}.
	 * @param logoutSuccessUrl the URL to redirect to after logout occurred
	 * @return the {@link Saml2LogoutConfigurer} for further customization
	 */
	public Saml2LogoutConfigurer<H> logoutSuccessUrl(String logoutSuccessUrl) {
		SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
		logoutSuccessHandler.setDefaultTargetUrl(logoutSuccessUrl);
		this.logoutSuccessHandler = logoutSuccessHandler;
		return this;
	}

	/**
	 * Sets the {@link LogoutSuccessHandler} to use. If this is specified,
	 * {@link #logoutSuccessUrl(String)} is ignored.
	 * @param logoutSuccessHandler the {@link LogoutSuccessHandler} to use after a user
	 * has been logged out.
	 * @return the {@link Saml2LogoutConfigurer} for further customizations
	 */
	public Saml2LogoutConfigurer<H> logoutSuccessHandler(LogoutSuccessHandler logoutSuccessHandler) {
		this.logoutSuccessHandler = logoutSuccessHandler;
		return this;
	}

	/**
	 * Allows specifying the names of cookies to be removed on logout success. This is a
	 * shortcut to easily invoke {@link #addLogoutHandler(LogoutHandler)} with a
	 * {@link CookieClearingLogoutHandler}.
	 * @param cookieNamesToClear the names of cookies to be removed on logout success.
	 * @return the {@link Saml2LogoutConfigurer} for further customization
	 */
	public Saml2LogoutConfigurer<H> deleteCookies(String... cookieNamesToClear) {
		return addLogoutHandler(new CookieClearingLogoutHandler(cookieNamesToClear));
	}

	/**
	 * Sets the {@code RelyingPartyRegistrationRepository} of relying parties, each party
	 * representing a service provider, SP and this host, and identity provider, IDP pair
	 * that communicate with each other.
	 * @param repo the repository of relying parties
	 * @return the {@link Saml2LoginConfigurer} for further configuration
	 */
	public Saml2LogoutConfigurer<H> relyingPartyRegistrationRepository(RelyingPartyRegistrationRepository repo) {
		this.relyingPartyRegistrationRepository = repo;
		return this;
	}

	/**
	 * Get configurer for SAML 2.0 Logout Request components
	 * @return the {@link LogoutRequestConfigurer} for further customizations
	 */
	public LogoutRequestConfigurer logoutRequest() {
		return this.logoutRequestConfigurer;
	}

	/**
	 * Configures SAML 2.0 Logout Request components
	 * @param logoutRequestConfigurerCustomizer the {@link Customizer} to provide more
	 * options for the {@link LogoutRequestConfigurer}
	 * @return the {@link Saml2LogoutConfigurer} for further customizations
	 */
	public Saml2LogoutConfigurer<H> logoutRequest(
			Customizer<LogoutRequestConfigurer> logoutRequestConfigurerCustomizer) {
		logoutRequestConfigurerCustomizer.customize(this.logoutRequestConfigurer);
		return this;
	}

	/**
	 * Get configurer for SAML 2.0 Logout Response components
	 * @return the {@link LogoutResponseConfigurer} for further customizations
	 */
	public LogoutResponseConfigurer logoutResponse() {
		return this.logoutResponseConfigurer;
	}

	/**
	 * Configures SAML 2.0 Logout Request components
	 * @param logoutResponseConfigurerCustomizer the {@link Customizer} to provide more
	 * options for the {@link LogoutResponseConfigurer}
	 * @return the {@link Saml2LogoutConfigurer} for further customizations
	 */
	public Saml2LogoutConfigurer<H> logoutResponse(
			Customizer<LogoutResponseConfigurer> logoutResponseConfigurerCustomizer) {
		logoutResponseConfigurerCustomizer.customize(this.logoutResponseConfigurer);
		return this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void configure(H http) throws Exception {
		RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = getRelyingPartyRegistrationResolver(http);
		CsrfTokenRepository csrfTokenRepository = http.getSharedObject(CsrfTokenRepository.class);
		if (csrfTokenRepository != null) {
			this.logoutHandlers.add(new CsrfLogoutHandler(csrfTokenRepository));
		}
		this.logoutHandlers.add(this.contextLogoutHandler);
		this.logoutHandlers.add(postProcess(new LogoutSuccessEventPublishingLogoutHandler()));
		LogoutFilter logoutFilter = createLogoutFilter(http, this.logoutHandlers, relyingPartyRegistrationResolver);
		http.addFilterBefore(logoutFilter, LogoutFilter.class);
		Saml2LogoutRequestFilter logoutRequestFilter = createLogoutRequestFilter(this.logoutHandlers,
				relyingPartyRegistrationResolver);
		http.addFilterBefore(logoutRequestFilter, LogoutFilter.class);
		Saml2LogoutResponseFilter logoutResponseFilter = createLogoutResponseFilter(relyingPartyRegistrationResolver);
		logoutResponseFilter.setLogoutSuccessHandler(getLogoutSuccessHandler());
		http.addFilterBefore(logoutResponseFilter, LogoutFilter.class);
	}

	/**
	 * Returns true if the logout success has been customized via
	 * {@link #logoutSuccessUrl(String)} or
	 * {@link #logoutSuccessHandler(LogoutSuccessHandler)}.
	 * @return true if logout success handling has been customized, else false
	 */
	boolean isCustomLogoutSuccess() {
		return this.logoutSuccessHandler != null;
	}

	private RelyingPartyRegistrationResolver getRelyingPartyRegistrationResolver(H http) {
		RelyingPartyRegistrationRepository registrations = getRelyingPartyRegistrationRepository();
		return new DefaultRelyingPartyRegistrationResolver(registrations);
	}

	private RelyingPartyRegistrationRepository getRelyingPartyRegistrationRepository() {
		if (this.relyingPartyRegistrationRepository == null) {
			this.relyingPartyRegistrationRepository = getBeanOrNull(RelyingPartyRegistrationRepository.class);
		}
		return this.relyingPartyRegistrationRepository;
	}

	private LogoutFilter createLogoutFilter(H http, List<LogoutHandler> logoutHandlers,
			RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		LogoutHandler[] handlers = logoutHandlers.toArray(new LogoutHandler[0]);
		LogoutSuccessHandler logoutRequestSuccessHandler = this.logoutRequestConfigurer
				.logoutRequestSuccessHandler(relyingPartyRegistrationResolver);
		LogoutSuccessHandler finalSuccessHandler = getLogoutSuccessHandler();
		LogoutSuccessHandler logoutSuccessHandler = (request, response, authentication) -> {
			if (authentication == null) {
				finalSuccessHandler.onLogoutSuccess(request, response, authentication);
			}
			else {
				logoutRequestSuccessHandler.onLogoutSuccess(request, response, authentication);
			}
		};
		LogoutFilter result = new LogoutFilter(logoutSuccessHandler, handlers) {
			@Override
			protected boolean requiresLogout(HttpServletRequest request, HttpServletResponse response) {
				Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
				if (!(authentication instanceof Saml2Authentication)) {
					return false;
				}
				return super.requiresLogout(request, response);
			}
		};
		result.setLogoutRequestMatcher(getLogoutRequestMatcher(http));
		return postProcess(result);
	}

	private Saml2LogoutRequestFilter createLogoutRequestFilter(List<LogoutHandler> logoutHandlers,
			RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		LogoutHandler logoutRequestHandler = this.logoutRequestConfigurer
				.logoutRequestHandler(relyingPartyRegistrationResolver);
		List<LogoutHandler> handlers = new ArrayList<>();
		handlers.add(logoutRequestHandler);
		handlers.addAll(logoutHandlers);
		Saml2LogoutRequestFilter logoutRequestFilter = new Saml2LogoutRequestFilter(
				this.logoutResponseConfigurer.logoutResponseSuccessHandler(relyingPartyRegistrationResolver),
				new CompositeLogoutHandler(handlers));
		logoutRequestFilter.setLogoutRequestMatcher(this.logoutRequestConfigurer.requestMatcher);
		CsrfConfigurer<H> csrf = getBuilder().getConfigurer(CsrfConfigurer.class);
		if (csrf != null) {
			csrf.ignoringRequestMatchers(this.logoutRequestConfigurer.requestMatcher);
		}
		return logoutRequestFilter;
	}

	private Saml2LogoutResponseFilter createLogoutResponseFilter(
			RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		Saml2LogoutResponseFilter logoutResponseFilter = new Saml2LogoutResponseFilter(
				this.logoutResponseConfigurer.logoutResponseHandler(relyingPartyRegistrationResolver));
		logoutResponseFilter.setLogoutRequestMatcher(this.logoutResponseConfigurer.requestMatcher);
		CsrfConfigurer<H> csrf = getBuilder().getConfigurer(CsrfConfigurer.class);
		if (csrf != null) {
			csrf.ignoringRequestMatchers(this.logoutResponseConfigurer.requestMatcher);
		}
		logoutResponseFilter.setLogoutSuccessHandler(getLogoutSuccessHandler());
		return logoutResponseFilter;
	}

	private RequestMatcher getLogoutRequestMatcher(H http) {
		if (this.logoutRequestMatcher != null) {
			return this.logoutRequestMatcher;
		}
		this.logoutRequestMatcher = createLogoutRequestMatcher(http);
		return this.logoutRequestMatcher;
	}

	@SuppressWarnings("unchecked")
	private RequestMatcher createLogoutRequestMatcher(H http) {
		RequestMatcher post = createLogoutRequestMatcher("POST");
		if (http.getConfigurer(CsrfConfigurer.class) != null) {
			return post;
		}
		RequestMatcher get = createLogoutRequestMatcher("GET");
		return new OrRequestMatcher(get, post);
	}

	private RequestMatcher createLogoutRequestMatcher(String httpMethod) {
		return new AntPathRequestMatcher(this.logoutUrl, httpMethod);
	}

	private LogoutSuccessHandler getLogoutSuccessHandler() {
		if (this.logoutSuccessHandler != null) {
			return this.logoutSuccessHandler;
		}
		SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
		logoutSuccessHandler.setDefaultTargetUrl(this.logoutSuccessUrl);
		this.logoutSuccessHandler = logoutSuccessHandler;
		return logoutSuccessHandler;
	}

	private <C> C getBeanOrNull(Class<C> clazz) {
		if (this.context == null) {
			return null;
		}
		if (this.context.getBeanNamesForType(clazz).length == 0) {
			return null;
		}
		return this.context.getBean(clazz);
	}

	/**
	 * A configurer for SAML 2.0 LogoutRequest components
	 */
	public final class LogoutRequestConfigurer {

		private RequestMatcher requestMatcher = new AntPathRequestMatcher("/logout/saml2/slo");

		private LogoutHandler logoutHandler;

		private LogoutSuccessHandler logoutSuccessHandler;

		private Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

		LogoutRequestConfigurer() {
		}

		/**
		 * Use this {@link RequestMatcher} for recognizing a logout request from the
		 * asserting party
		 *
		 * <p>
		 * Defaults to {@code /logout/saml2}
		 * @param requestMatcher the {@link RequestMatcher} to use
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 */
		public LogoutRequestConfigurer logoutRequestMatcher(RequestMatcher requestMatcher) {
			this.requestMatcher = requestMatcher;
			return this;
		}

		/**
		 * Use this {@link LogoutHandler} for processing a logout request from the
		 * asserting party
		 * @param logoutHandler the {@link LogoutHandler} to use
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 */
		public LogoutRequestConfigurer logoutRequestHandler(LogoutHandler logoutHandler) {
			this.logoutHandler = logoutHandler;
			return this;
		}

		/**
		 * Use this {@link Saml2LogoutRequestResolver} for producing a logout request to
		 * send to the asserting party
		 * @param logoutRequestResolver the {@link Saml2LogoutRequestResolver} to use
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 */
		public LogoutRequestConfigurer logoutRequestResolver(Saml2LogoutRequestResolver logoutRequestResolver) {
			this.logoutSuccessHandler = new Saml2LogoutRequestSuccessHandler(logoutRequestResolver);
			return this;
		}

		/**
		 * Use this {@link Saml2LogoutRequestRepository} for storing logout requests
		 * @param logoutRequestRepository the {@link Saml2LogoutRequestRepository} to use
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 */
		public LogoutRequestConfigurer logoutRequestRepository(Saml2LogoutRequestRepository logoutRequestRepository) {
			this.logoutRequestRepository = logoutRequestRepository;
			return this;
		}

		public Saml2LogoutConfigurer<H> and() {
			return Saml2LogoutConfigurer.this;
		}

		private LogoutHandler logoutRequestHandler(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
			if (this.logoutHandler == null) {
				return new OpenSamlLogoutRequestHandler(relyingPartyRegistrationResolver);
			}
			return this.logoutHandler;
		}

		private LogoutSuccessHandler logoutRequestSuccessHandler(
				RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
			if (this.logoutSuccessHandler == null) {
				Saml2LogoutRequestSuccessHandler logoutSuccessHandler = new Saml2LogoutRequestSuccessHandler(
						logoutRequestResolver(relyingPartyRegistrationResolver));
				logoutSuccessHandler.setLogoutRequestRepository(this.logoutRequestRepository);
				return logoutSuccessHandler;
			}
			return this.logoutSuccessHandler;
		}

		private Saml2LogoutRequestResolver logoutRequestResolver(
				RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
			if (Version.getVersion().startsWith("4")) {
				return new OpenSaml4LogoutRequestResolver(relyingPartyRegistrationResolver);
			}
			return new OpenSaml3LogoutRequestResolver(relyingPartyRegistrationResolver);
		}

	}

	public final class LogoutResponseConfigurer {

		private final LogoutRequestConfigurer logoutRequest;

		private RequestMatcher requestMatcher = new AntPathRequestMatcher("/logout/saml2/slo");

		private LogoutHandler logoutHandler;

		private LogoutSuccessHandler logoutSuccessHandler;

		LogoutResponseConfigurer(LogoutRequestConfigurer logoutRequest) {
			this.logoutRequest = logoutRequest;
		}

		/**
		 * Use this {@link RequestMatcher} for recognizing a logout response from the
		 * asserting party
		 *
		 * <p>
		 * Defaults to {@code /logout/saml2}
		 * @param requestMatcher the {@link RequestMatcher} to use
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 */
		public LogoutResponseConfigurer logoutRequestMatcher(RequestMatcher requestMatcher) {
			this.requestMatcher = requestMatcher;
			return this;
		}

		/**
		 * Use this {@link LogoutHandler} for processing a logout response from the
		 * asserting party
		 * @param logoutHandler the {@link LogoutHandler} to use
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 */
		public LogoutResponseConfigurer logoutResponseHandler(LogoutHandler logoutHandler) {
			this.logoutHandler = logoutHandler;
			return this;
		}

		/**
		 * Use this {@link Saml2LogoutRequestResolver} for producing a logout response to
		 * send to the asserting party
		 * @param logoutResponseResolver the {@link Saml2LogoutResponseResolver} to use
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 */
		public LogoutResponseConfigurer logoutResponseResolver(Saml2LogoutResponseResolver logoutResponseResolver) {
			this.logoutSuccessHandler = new Saml2LogoutResponseSuccessHandler(logoutResponseResolver);
			return this;
		}

		public Saml2LogoutConfigurer<H> and() {
			return Saml2LogoutConfigurer.this;
		}

		private LogoutHandler logoutResponseHandler(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
			if (this.logoutHandler == null) {
				OpenSamlLogoutResponseHandler logoutHandler = new OpenSamlLogoutResponseHandler(
						relyingPartyRegistrationResolver);
				logoutHandler.setLogoutRequestRepository(this.logoutRequest.logoutRequestRepository);
				return logoutHandler;
			}
			return this.logoutHandler;
		}

		private LogoutSuccessHandler logoutResponseSuccessHandler(
				RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
			if (this.logoutSuccessHandler == null) {
				return new Saml2LogoutResponseSuccessHandler(logoutResponseResolver(relyingPartyRegistrationResolver));
			}
			return this.logoutSuccessHandler;
		}

		private Saml2LogoutResponseResolver logoutResponseResolver(
				RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
			if (Version.getVersion().startsWith("4")) {
				return new OpenSaml4LogoutResponseResolver(relyingPartyRegistrationResolver);
			}
			return new OpenSaml3LogoutResponseResolver(relyingPartyRegistrationResolver);
		}

	}

}
