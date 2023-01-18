/*
 * Copyright 2002-2023 the original author or authors.
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

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
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

		private LogoutHandler logoutHandler;

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
			if (this.logoutHandler == null) {
				OidcBackChannelLogoutHandler logoutHandler = new OidcBackChannelLogoutHandler();
				logoutHandler.setSessionRegistry(OAuth2ClientConfigurerUtils.getOidcSessionRegistry(http));
				this.logoutHandler = logoutHandler;
			}
			return this.logoutHandler;
		}

		void configure(B http) {
			OidcBackChannelLogoutFilter filter = new OidcBackChannelLogoutFilter(authenticationConverter(http),
					authenticationManager());
			filter.setLogoutHandler(logoutHandler(http));
			http.addFilterBefore(filter, CsrfFilter.class);
		}

	}

}
