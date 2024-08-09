/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.util.function.Consumer;
import java.util.function.Function;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.util.Assert;

/**
 * An {@link AbstractHttpConfigurer} for OIDC Logout flows
 *
 * <p>
 * OIDC Logout provides an application with the capability to have users log out by using
 * their existing account at an OAuth 2.0 or OpenID Connect 1.0 Provider.
 *
 *
 * <h2>Security Filters</h2>
 *
 * The following {@code Filter} is populated:
 *
 * <ul>
 * <li>{@link OidcBackChannelLogoutFilter}</li>
 * </ul>
 *
 * <h2>Shared Objects Used</h2>
 *
 * The following shared objects are used:
 *
 * <ul>
 * <li>{@link ClientRegistrationRepository}</li>
 * </ul>
 *
 * @author Josh Cummings
 * @since 6.2
 * @see HttpSecurity#oidcLogout()
 * @see OidcBackChannelLogoutFilter
 * @see ClientRegistrationRepository
 */
public final class OidcLogoutConfigurer<B extends HttpSecurityBuilder<B>>
		extends AbstractHttpConfigurer<OidcLogoutConfigurer<B>, B> {

	private BackChannelLogoutConfigurer backChannel;

	/**
	 * Sets the repository of client registrations.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @return the {@link OAuth2LoginConfigurer} for further configuration
	 */
	public OidcLogoutConfigurer<B> clientRegistrationRepository(
			ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	/**
	 * Sets the registry for managing the OIDC client-provider session link
	 * @param oidcSessionRegistry the {@link OidcSessionRegistry} to use
	 * @return the {@link OAuth2LoginConfigurer} for further configuration
	 */
	public OidcLogoutConfigurer<B> oidcSessionRegistry(OidcSessionRegistry oidcSessionRegistry) {
		Assert.notNull(oidcSessionRegistry, "oidcSessionRegistry cannot be null");
		getBuilder().setSharedObject(OidcSessionRegistry.class, oidcSessionRegistry);
		return this;
	}

	/**
	 * Configure OIDC Back-Channel Logout using the provided {@link Consumer}
	 * @return the {@link OidcLogoutConfigurer} for further configuration
	 */
	public OidcLogoutConfigurer<B> backChannel(Customizer<BackChannelLogoutConfigurer> backChannelLogoutConfigurer) {
		if (this.backChannel == null) {
			this.backChannel = new BackChannelLogoutConfigurer();
		}
		backChannelLogoutConfigurer.customize(this.backChannel);
		return this;
	}

	@Deprecated(forRemoval = true, since = "6.2")
	public B and() {
		return getBuilder();
	}

	@Override
	public void configure(B builder) throws Exception {
		if (this.backChannel != null) {
			this.backChannel.configure(builder);
		}
	}

	/**
	 * A configurer for configuring OIDC Back-Channel Logout
	 */
	public final class BackChannelLogoutConfigurer {

		private AuthenticationConverter authenticationConverter;

		private final AuthenticationManager authenticationManager = new ProviderManager(
				new OidcBackChannelLogoutAuthenticationProvider());

		private Function<B, LogoutHandler> logoutHandler = this::logoutHandler;

		private AuthenticationConverter authenticationConverter(B http) {
			if (this.authenticationConverter == null) {
				ClientRegistrationRepository clientRegistrationRepository = OAuth2ClientConfigurerUtils
					.getClientRegistrationRepository(http);
				this.authenticationConverter = new OidcLogoutAuthenticationConverter(clientRegistrationRepository);
			}
			return this.authenticationConverter;
		}

		private AuthenticationManager authenticationManager() {
			return this.authenticationManager;
		}

		private LogoutHandler logoutHandler(B http) {
			OidcBackChannelLogoutHandler logoutHandler = new OidcBackChannelLogoutHandler();
			logoutHandler.setSessionRegistry(OAuth2ClientConfigurerUtils.getOidcSessionRegistry(http));
			return logoutHandler;
		}

		/**
		 * Use this endpoint when invoking a back-channel logout.
		 *
		 * <p>
		 * The resulting {@link LogoutHandler} will {@code POST} the session cookie and
		 * CSRF token to this endpoint to invalidate the corresponding end-user session.
		 *
		 * <p>
		 * Supports URI templates like {@code {baseUrl}}, {@code {baseScheme}}, and
		 * {@code {basePort}}.
		 *
		 * <p>
		 * By default, the URI is set to
		 * {@code {baseScheme}://localhost{basePort}/logout}, meaning that the scheme and
		 * port of the original back-channel request is preserved, while the host and
		 * endpoint are changed.
		 *
		 * <p>
		 * If you are using Spring Security for the logout endpoint, the path part of this
		 * URI should match the value configured there.
		 *
		 * <p>
		 * Otherwise, this is handy in the event that your server configuration means that
		 * the scheme, server name, or port in the {@code Host} header are different from
		 * how you would address the same server internally.
		 * @param logoutUri the URI to request logout on the back-channel
		 * @return the {@link BackChannelLogoutConfigurer} for further customizations
		 * @since 6.2.4
		 * @deprecated Please use {@link #sessionLogout} instead
		 */
		@Deprecated
		public BackChannelLogoutConfigurer logoutUri(String logoutUri) {
			this.logoutHandler = (http) -> {
				OidcBackChannelLogoutHandler logoutHandler = new OidcBackChannelLogoutHandler();
				logoutHandler.setSessionRegistry(OAuth2ClientConfigurerUtils.getOidcSessionRegistry(http));
				logoutHandler.setLogoutUri(logoutUri);
				return logoutHandler;
			};
			return this;
		}

		/**
		 * Configure what and how per-session logout will be performed.
		 *
		 * <p>
		 * This overrides any value given to {@link #logoutUri(String)}
		 *
		 * <p>
		 * By default, the resulting {@link LogoutHandler} will {@code POST} the session
		 * cookie and OIDC logout token back to the original back-channel logout endpoint.
		 *
		 * <p>
		 * Using this method changes the underlying default that {@code POST}s the session
		 * cookie and CSRF token to your application's {@code /logout} endpoint. As such,
		 * it is recommended to call this instead of accepting the {@code /logout} default
		 * as this does not require any special CSRF configuration, even if you don't
		 * require other changes.
		 *
		 * <p>
		 * For example, configuring Back-Channel Logout in the following way:
		 *
		 * <pre>
		 * 	http
		 *     	.oidcLogout((oidc) -> oidc
		 *     		.backChannel((backChannel) -> backChannel
		 *     			.sessionLogout(Customizer.withDefaults())
		 *     		)
		 *     	);
		 * </pre>
		 *
		 * will make so that the per-session logout invocation no longer requires special
		 * CSRF configurations.
		 *
		 * <p>
		 * By default, the URI is set to
		 * {@code {baseScheme}://localhost{basePort}/logout/connect/back-channel/{registrationId}},
		 * which is simply an internal version of the same endpoint exposed to your
		 * Back-Channel services. You can use {@link SessionLogoutConfigurer#logoutUri} to
		 * alter the scheme, server name, or port in the {@code Host} header to
		 * accommodate how your application would address itself internally.
		 *
		 * <p>
		 * For example, if the way your application would internally call itself is on a
		 * different scheme and port than incoming traffic, you can configure the endpoint
		 * in the following way:
		 *
		 * <pre>
		 * 	http
		 * 		.oidcLogout((oidc) -&gt; oidc
		 * 			.backChannel((backChannel) -&gt; backChannel
		 * 				.sessionLogout((logout) -&gt; logout
		 * 					.uri("http://localhost:9000/logout/connect/back-channel/{registrationId}")
		 * 				)
		 * 			)
		 * 		);
		 * </pre>
		 * @param sessionLogout a {@link Customizer} for configuring how to log out of
		 * each individual session
		 * @return {@link BackChannelLogoutConfigurer} for further customizations
		 * @since 6.4
		 */
		public BackChannelLogoutConfigurer sessionLogout(Customizer<SessionLogoutConfigurer> sessionLogout) {
			this.logoutHandler = (http) -> {
				SessionLogoutConfigurer logoutHandler = new SessionLogoutConfigurer();
				sessionLogout.customize(logoutHandler);
				return logoutHandler.configure(http);
			};
			return this;
		}

		void configure(B http) {
			OidcBackChannelLogoutFilter filter = new OidcBackChannelLogoutFilter(authenticationConverter(http),
					authenticationManager());
			LogoutHandler oidcLogout = this.logoutHandler.apply(http);
			LogoutHandler sessionLogout = new SecurityContextLogoutHandler();
			LogoutConfigurer<B> logout = http.getConfigurer(LogoutConfigurer.class);
			if (logout != null) {
				sessionLogout = new CompositeLogoutHandler(logout.getLogoutHandlers());
			}
			filter.setLogoutHandler(new EitherLogoutHandler(oidcLogout, sessionLogout));
			http.addFilterBefore(filter, CsrfFilter.class);
		}

		private static final class EitherLogoutHandler implements LogoutHandler {

			private final LogoutHandler left;

			private final LogoutHandler right;

			EitherLogoutHandler(LogoutHandler left, LogoutHandler right) {
				this.left = left;
				this.right = right;
			}

			@Override
			public void logout(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) {
				if (request.getParameter("_spring_security_internal_logout") == null) {
					this.left.logout(request, response, authentication);
				}
				else {
					this.right.logout(request, response, authentication);
				}
			}

		}

		/**
		 * A configurer for logging out each internal session as identified by the
		 * external session listed in the OIDC Logout Token.
		 *
		 * @author Josh Cummings
		 * @since 6.4
		 */
		public final class SessionLogoutConfigurer {

			private String logoutUri = "{baseScheme}://localhost{basePort}/logout/connect/back-channel/{registrationId}";

			private String cookieName = "JSESSIONID";

			private SessionLogoutConfigurer() {

			}

			/**
			 * Use this URI to log out a specific session indicated by the OIDC Logout
			 * Token.
			 *
			 * <p>
			 * Defaults to pointing back to the original Back-Channel OIDC endpoint, now
			 * including the session cookie value that corresponds to the {@code sid}
			 * referenced in the OIDC Logout Token.
			 *
			 * <p>
			 * This default value is
			 * {@code {baseScheme}://localhost{basePort}/logout/connect/back-channel/{registrationId}}
			 *
			 * <p>
			 * If needed for backward compatibility, you can also set this to a different
			 * logout endpoint, like the Spring Security logout endpoint:
			 * {@code {baseScheme}://localhost{basePort}/logout}.
			 * @param uri the URI to invoke to log out specific sessions
			 * @return the {@link SessionLogoutConfigurer} for further customizations
			 */
			public SessionLogoutConfigurer uri(String uri) {
				this.logoutUri = uri;
				return this;
			}

			/**
			 * Use this cookie name to propagate the internal session identifier in the
			 * internal logout invocation.
			 *
			 * <p>
			 * This defaults to {@code JSESSIONID}.
			 *
			 * <p>
			 * When using Spring Session, you may need to set this to {@code SESSION}
			 * @param cookieName the cookie name to use
			 * @return the {@link SessionLogoutConfigurer} for further customizations
			 */
			public SessionLogoutConfigurer cookieName(String cookieName) {
				this.cookieName = cookieName;
				return this;
			}

			private LogoutHandler configure(B http) {
				OidcBackChannelLogoutHandler logoutHandler = new OidcBackChannelLogoutHandler();
				logoutHandler.setSessionRegistry(OAuth2ClientConfigurerUtils.getOidcSessionRegistry(http));
				logoutHandler.setLogoutUri(this.logoutUri);
				logoutHandler.setSessionCookieName(this.cookieName);
				return logoutHandler;
			}

		}

	}

}
