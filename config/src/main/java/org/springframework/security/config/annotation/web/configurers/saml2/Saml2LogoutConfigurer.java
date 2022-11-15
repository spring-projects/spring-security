/*
 * Copyright 2002-2022 the original author or authors.
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
import java.util.Objects;
import java.util.function.Predicate;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlLogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlLogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.HttpSessionLogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestRepository;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

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
 * <li>{@link #logoutUrl} - The URL to to process SAML 2.0 Logout</li>
 * <li>{@link LogoutRequestConfigurer#logoutRequestValidator} - The
 * {@link AuthenticationManager} for authenticating SAML 2.0 Logout Requests</li>
 * <li>{@link LogoutRequestConfigurer#logoutRequestResolver} - The
 * {@link Saml2LogoutRequestResolver} for creating SAML 2.0 Logout Requests</li>
 * <li>{@link LogoutRequestConfigurer#logoutRequestRepository} - The
 * {@link Saml2LogoutRequestRepository} for storing SAML 2.0 Logout Requests</li>
 * <li>{@link LogoutResponseConfigurer#logoutResponseValidator} - The
 * {@link AuthenticationManager} for authenticating SAML 2.0 Logout Responses</li>
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
 * @since 5.6
 * @see Saml2LogoutConfigurer
 */
public final class Saml2LogoutConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<Saml2LogoutConfigurer<H>, H> {

	private ApplicationContext context;

	private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

	private String logoutUrl = "/logout";

	private List<LogoutHandler> logoutHandlers = new ArrayList<>();

	private LogoutSuccessHandler logoutSuccessHandler;

	private LogoutRequestConfigurer logoutRequestConfigurer;

	private LogoutResponseConfigurer logoutResponseConfigurer;

	/**
	 * Creates a new instance
	 * @see HttpSecurity#logout()
	 */
	public Saml2LogoutConfigurer(ApplicationContext context) {
		this.context = context;
		this.logoutHandlers.add(new SecurityContextLogoutHandler());
		this.logoutHandlers.add(new LogoutSuccessEventPublishingLogoutHandler());
		SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
		logoutSuccessHandler.setDefaultTargetUrl("/login?logout");
		this.logoutSuccessHandler = logoutSuccessHandler;
		this.logoutRequestConfigurer = new LogoutRequestConfigurer();
		this.logoutResponseConfigurer = new LogoutResponseConfigurer();
	}

	/**
	 * The URL by which the relying or asserting party can trigger logout.
	 *
	 * <p>
	 * The Relying Party triggers logout by POSTing to the endpoint. The Asserting Party
	 * triggers logout based on what is specified by
	 * {@link RelyingPartyRegistration#getSingleLogoutServiceBindings()}.
	 * @param logoutUrl the URL that will invoke logout
	 * @return the {@link LogoutConfigurer} for further customizations
	 * @see LogoutConfigurer#logoutUrl(String)
	 * @see HttpSecurity#csrf()
	 */
	public Saml2LogoutConfigurer<H> logoutUrl(String logoutUrl) {
		this.logoutUrl = logoutUrl;
		return this;
	}

	/**
	 * Sets the {@link RelyingPartyRegistrationRepository} of relying parties, each party
	 * representing a service provider, SP and this host, and identity provider, IDP pair
	 * that communicate with each other.
	 * @param repo the repository of relying parties
	 * @return the {@link Saml2LogoutConfigurer} for further customizations
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
		LogoutConfigurer<H> logout = http.getConfigurer(LogoutConfigurer.class);
		if (logout != null) {
			this.logoutHandlers = logout.getLogoutHandlers();
			this.logoutSuccessHandler = logout.getLogoutSuccessHandler();
		}
		RelyingPartyRegistrationResolver registrations = relyingPartyRegistrationResolver(http);
		http.addFilterBefore(createLogoutRequestProcessingFilter(registrations), CsrfFilter.class);
		http.addFilterBefore(createLogoutResponseProcessingFilter(registrations), CsrfFilter.class);
		http.addFilterBefore(createRelyingPartyLogoutFilter(registrations), LogoutFilter.class);
	}

	private RelyingPartyRegistrationResolver relyingPartyRegistrationResolver(H http) {
		RelyingPartyRegistrationRepository registrations = getRelyingPartyRegistrationRepository(http);
		return new DefaultRelyingPartyRegistrationResolver(registrations);
	}

	private RelyingPartyRegistrationRepository getRelyingPartyRegistrationRepository(H http) {
		if (this.relyingPartyRegistrationRepository != null) {
			return this.relyingPartyRegistrationRepository;
		}
		Saml2LoginConfigurer<H> login = http.getConfigurer(Saml2LoginConfigurer.class);
		if (login != null) {
			this.relyingPartyRegistrationRepository = login.relyingPartyRegistrationRepository(http);
		}
		else {
			this.relyingPartyRegistrationRepository = getBeanOrNull(RelyingPartyRegistrationRepository.class);
		}
		return this.relyingPartyRegistrationRepository;
	}

	private Saml2LogoutRequestFilter createLogoutRequestProcessingFilter(
			RelyingPartyRegistrationResolver registrations) {
		LogoutHandler[] logoutHandlers = this.logoutHandlers.toArray(new LogoutHandler[0]);
		Saml2LogoutResponseResolver logoutResponseResolver = createSaml2LogoutResponseResolver(registrations);
		Saml2LogoutRequestFilter filter = new Saml2LogoutRequestFilter(registrations,
				this.logoutRequestConfigurer.logoutRequestValidator(), logoutResponseResolver, logoutHandlers);
		filter.setLogoutRequestMatcher(createLogoutRequestMatcher());
		filter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
		return postProcess(filter);
	}

	private Saml2LogoutResponseFilter createLogoutResponseProcessingFilter(
			RelyingPartyRegistrationResolver registrations) {
		Saml2LogoutResponseFilter logoutResponseFilter = new Saml2LogoutResponseFilter(registrations,
				this.logoutResponseConfigurer.logoutResponseValidator(), this.logoutSuccessHandler);
		logoutResponseFilter.setLogoutRequestMatcher(createLogoutResponseMatcher());
		logoutResponseFilter.setLogoutRequestRepository(this.logoutRequestConfigurer.logoutRequestRepository);
		return postProcess(logoutResponseFilter);
	}

	private LogoutFilter createRelyingPartyLogoutFilter(RelyingPartyRegistrationResolver registrations) {
		LogoutHandler[] logoutHandlers = this.logoutHandlers.toArray(new LogoutHandler[0]);
		Saml2RelyingPartyInitiatedLogoutSuccessHandler logoutRequestSuccessHandler = createSaml2LogoutRequestSuccessHandler(
				registrations);
		logoutRequestSuccessHandler.setLogoutRequestRepository(this.logoutRequestConfigurer.logoutRequestRepository);
		LogoutFilter logoutFilter = new LogoutFilter(logoutRequestSuccessHandler, logoutHandlers);
		logoutFilter.setLogoutRequestMatcher(createLogoutMatcher());
		return postProcess(logoutFilter);
	}

	private RequestMatcher createLogoutMatcher() {
		RequestMatcher logout = new AntPathRequestMatcher(this.logoutUrl, "POST");
		RequestMatcher saml2 = new Saml2RequestMatcher(getSecurityContextHolderStrategy());
		return new AndRequestMatcher(logout, saml2);
	}

	private RequestMatcher createLogoutRequestMatcher() {
		RequestMatcher logout = new AntPathRequestMatcher(this.logoutRequestConfigurer.logoutUrl);
		RequestMatcher samlRequest = new ParameterRequestMatcher("SAMLRequest");
		return new AndRequestMatcher(logout, samlRequest);
	}

	private RequestMatcher createLogoutResponseMatcher() {
		RequestMatcher logout = new AntPathRequestMatcher(this.logoutResponseConfigurer.logoutUrl);
		RequestMatcher samlResponse = new ParameterRequestMatcher("SAMLResponse");
		return new AndRequestMatcher(logout, samlResponse);
	}

	private Saml2RelyingPartyInitiatedLogoutSuccessHandler createSaml2LogoutRequestSuccessHandler(
			RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		Saml2LogoutRequestResolver logoutRequestResolver = this.logoutRequestConfigurer
				.logoutRequestResolver(relyingPartyRegistrationResolver);
		return new Saml2RelyingPartyInitiatedLogoutSuccessHandler(logoutRequestResolver);
	}

	private Saml2LogoutResponseResolver createSaml2LogoutResponseResolver(
			RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		return this.logoutResponseConfigurer.logoutResponseResolver(relyingPartyRegistrationResolver);
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

		private String logoutUrl = "/logout/saml2/slo";

		private Saml2LogoutRequestValidator logoutRequestValidator;

		private Saml2LogoutRequestResolver logoutRequestResolver;

		private Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

		LogoutRequestConfigurer() {
		}

		/**
		 * The URL by which the asserting party can send a SAML 2.0 Logout Request
		 *
		 * <p>
		 * The Asserting Party should use whatever HTTP method specified in
		 * {@link RelyingPartyRegistration#getSingleLogoutServiceBindings()}.
		 * @param logoutUrl the URL that will receive the SAML 2.0 Logout Request
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 * @see Saml2LogoutConfigurer#logoutUrl(String)
		 */
		public LogoutRequestConfigurer logoutUrl(String logoutUrl) {
			this.logoutUrl = logoutUrl;
			return this;
		}

		/**
		 * Use this {@link LogoutHandler} for processing a logout request from the
		 * asserting party
		 * @param authenticator the {@link Saml2LogoutRequestValidator} to use
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 */
		public LogoutRequestConfigurer logoutRequestValidator(Saml2LogoutRequestValidator authenticator) {
			this.logoutRequestValidator = authenticator;
			return this;
		}

		/**
		 * Use this {@link Saml2LogoutRequestResolver} for producing a logout request to
		 * send to the asserting party
		 * @param logoutRequestResolver the {@link Saml2LogoutRequestResolver} to use
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 */
		public LogoutRequestConfigurer logoutRequestResolver(Saml2LogoutRequestResolver logoutRequestResolver) {
			this.logoutRequestResolver = logoutRequestResolver;
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

		private Saml2LogoutRequestValidator logoutRequestValidator() {
			if (this.logoutRequestValidator == null) {
				return new OpenSamlLogoutRequestValidator();
			}
			return this.logoutRequestValidator;
		}

		private Saml2LogoutRequestResolver logoutRequestResolver(
				RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
			if (this.logoutRequestResolver != null) {
				return this.logoutRequestResolver;
			}
			return new OpenSaml4LogoutRequestResolver(relyingPartyRegistrationResolver);
		}

	}

	public final class LogoutResponseConfigurer {

		private String logoutUrl = "/logout/saml2/slo";

		private Saml2LogoutResponseValidator logoutResponseValidator;

		private Saml2LogoutResponseResolver logoutResponseResolver;

		LogoutResponseConfigurer() {
		}

		/**
		 * The URL by which the asserting party can send a SAML 2.0 Logout Response
		 *
		 * <p>
		 * The Asserting Party should use whatever HTTP method specified in
		 * {@link RelyingPartyRegistration#getSingleLogoutServiceBindings()}.
		 * @param logoutUrl the URL that will receive the SAML 2.0 Logout Response
		 * @return the {@link LogoutResponseConfigurer} for further customizations
		 * @see Saml2LogoutConfigurer#logoutUrl(String)
		 */
		public LogoutResponseConfigurer logoutUrl(String logoutUrl) {
			this.logoutUrl = logoutUrl;
			return this;
		}

		/**
		 * Use this {@link LogoutHandler} for processing a logout response from the
		 * asserting party
		 * @param authenticator the {@link AuthenticationManager} to use
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 */
		public LogoutResponseConfigurer logoutResponseValidator(Saml2LogoutResponseValidator authenticator) {
			this.logoutResponseValidator = authenticator;
			return this;
		}

		/**
		 * Use this {@link Saml2LogoutRequestResolver} for producing a logout response to
		 * send to the asserting party
		 * @param logoutResponseResolver the {@link Saml2LogoutResponseResolver} to use
		 * @return the {@link LogoutRequestConfigurer} for further customizations
		 */
		public LogoutResponseConfigurer logoutResponseResolver(Saml2LogoutResponseResolver logoutResponseResolver) {
			this.logoutResponseResolver = logoutResponseResolver;
			return this;
		}

		public Saml2LogoutConfigurer<H> and() {
			return Saml2LogoutConfigurer.this;
		}

		private Saml2LogoutResponseValidator logoutResponseValidator() {
			if (this.logoutResponseValidator == null) {
				return new OpenSamlLogoutResponseValidator();
			}
			return this.logoutResponseValidator;
		}

		private Saml2LogoutResponseResolver logoutResponseResolver(
				RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
			if (this.logoutResponseResolver == null) {
				return new OpenSaml4LogoutResponseResolver(relyingPartyRegistrationResolver);
			}
			return this.logoutResponseResolver;
		}

	}

	private static class Saml2RequestMatcher implements RequestMatcher {

		private final SecurityContextHolderStrategy securityContextHolderStrategy;

		Saml2RequestMatcher(SecurityContextHolderStrategy securityContextHolderStrategy) {
			this.securityContextHolderStrategy = securityContextHolderStrategy;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
			if (authentication == null) {
				return false;
			}
			return authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal;
		}

	}

	private static class ParameterRequestMatcher implements RequestMatcher {

		Predicate<String> test = Objects::nonNull;

		String name;

		ParameterRequestMatcher(String name) {
			this.name = name;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return this.test.test(request.getParameter(this.name));
		}

	}

}
