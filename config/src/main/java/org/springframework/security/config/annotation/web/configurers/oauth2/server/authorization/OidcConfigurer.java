/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Configurer for OpenID Connect 1.0 support.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2AuthorizationServerConfigurer#oidc
 * @see OidcProviderConfigurationEndpointConfigurer
 * @see OidcLogoutEndpointConfigurer
 * @see OidcClientRegistrationEndpointConfigurer
 * @see OidcUserInfoEndpointConfigurer
 */
public final class OidcConfigurer extends AbstractOAuth2Configurer {

	private final Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers = new LinkedHashMap<>();

	private RequestMatcher requestMatcher;

	/**
	 * Restrict for internal use only.
	 * @param objectPostProcessor an {@code ObjectPostProcessor}
	 */
	OidcConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
		addConfigurer(OidcProviderConfigurationEndpointConfigurer.class,
				new OidcProviderConfigurationEndpointConfigurer(objectPostProcessor));
		addConfigurer(OidcLogoutEndpointConfigurer.class, new OidcLogoutEndpointConfigurer(objectPostProcessor));
		addConfigurer(OidcUserInfoEndpointConfigurer.class, new OidcUserInfoEndpointConfigurer(objectPostProcessor));
	}

	/**
	 * Configures the OpenID Connect 1.0 Provider Configuration Endpoint.
	 * @param providerConfigurationEndpointCustomizer the {@link Customizer} providing
	 * access to the {@link OidcProviderConfigurationEndpointConfigurer}
	 * @return the {@link OidcConfigurer} for further configuration
	 */
	public OidcConfigurer providerConfigurationEndpoint(
			Customizer<OidcProviderConfigurationEndpointConfigurer> providerConfigurationEndpointCustomizer) {
		providerConfigurationEndpointCustomizer
			.customize(getConfigurer(OidcProviderConfigurationEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OpenID Connect 1.0 RP-Initiated Logout Endpoint.
	 * @param logoutEndpointCustomizer the {@link Customizer} providing access to the
	 * {@link OidcLogoutEndpointConfigurer}
	 * @return the {@link OidcConfigurer} for further configuration
	 */
	public OidcConfigurer logoutEndpoint(Customizer<OidcLogoutEndpointConfigurer> logoutEndpointCustomizer) {
		logoutEndpointCustomizer.customize(getConfigurer(OidcLogoutEndpointConfigurer.class));
		return this;
	}

	/**
	 * Configures the OpenID Connect Dynamic Client Registration 1.0 Endpoint.
	 * @param clientRegistrationEndpointCustomizer the {@link Customizer} providing access
	 * to the {@link OidcClientRegistrationEndpointConfigurer}
	 * @return the {@link OidcConfigurer} for further configuration
	 */
	public OidcConfigurer clientRegistrationEndpoint(
			Customizer<OidcClientRegistrationEndpointConfigurer> clientRegistrationEndpointCustomizer) {
		OidcClientRegistrationEndpointConfigurer clientRegistrationEndpointConfigurer = getConfigurer(
				OidcClientRegistrationEndpointConfigurer.class);
		if (clientRegistrationEndpointConfigurer == null) {
			addConfigurer(OidcClientRegistrationEndpointConfigurer.class,
					new OidcClientRegistrationEndpointConfigurer(getObjectPostProcessor()));
			clientRegistrationEndpointConfigurer = getConfigurer(OidcClientRegistrationEndpointConfigurer.class);
		}
		clientRegistrationEndpointCustomizer.customize(clientRegistrationEndpointConfigurer);
		return this;
	}

	/**
	 * Configures the OpenID Connect 1.0 UserInfo Endpoint.
	 * @param userInfoEndpointCustomizer the {@link Customizer} providing access to the
	 * {@link OidcUserInfoEndpointConfigurer}
	 * @return the {@link OidcConfigurer} for further configuration
	 */
	public OidcConfigurer userInfoEndpoint(Customizer<OidcUserInfoEndpointConfigurer> userInfoEndpointCustomizer) {
		userInfoEndpointCustomizer.customize(getConfigurer(OidcUserInfoEndpointConfigurer.class));
		return this;
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		List<RequestMatcher> requestMatchers = new ArrayList<>();
		this.configurers.values().forEach((configurer) -> {
			configurer.init(httpSecurity);
			requestMatchers.add(configurer.getRequestMatcher());
		});
		this.requestMatcher = new OrRequestMatcher(requestMatchers);
	}

	@Override
	void configure(HttpSecurity httpSecurity) {
		OidcClientRegistrationEndpointConfigurer clientRegistrationEndpointConfigurer = getConfigurer(
				OidcClientRegistrationEndpointConfigurer.class);
		if (clientRegistrationEndpointConfigurer != null) {
			OidcProviderConfigurationEndpointConfigurer providerConfigurationEndpointConfigurer = getConfigurer(
					OidcProviderConfigurationEndpointConfigurer.class);

			providerConfigurationEndpointConfigurer.addDefaultProviderConfigurationCustomizer((builder) -> {
				AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
				String issuer = authorizationServerContext.getIssuer();
				AuthorizationServerSettings authorizationServerSettings = authorizationServerContext
					.getAuthorizationServerSettings();

				String clientRegistrationEndpoint = UriComponentsBuilder.fromUriString(issuer)
					.path(authorizationServerSettings.getOidcClientRegistrationEndpoint())
					.build()
					.toUriString();

				builder.clientRegistrationEndpoint(clientRegistrationEndpoint);
			});
		}

		OAuth2DeviceAuthorizationEndpointConfigurer deviceAuthorizationEndpointConfigurer = httpSecurity
			.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.getConfigurer(OAuth2DeviceAuthorizationEndpointConfigurer.class);
		if (deviceAuthorizationEndpointConfigurer != null) {
			OidcProviderConfigurationEndpointConfigurer providerConfigurationEndpointConfigurer = getConfigurer(
					OidcProviderConfigurationEndpointConfigurer.class);

			providerConfigurationEndpointConfigurer.addDefaultProviderConfigurationCustomizer((builder) -> {
				AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
				String issuer = authorizationServerContext.getIssuer();
				AuthorizationServerSettings authorizationServerSettings = authorizationServerContext
					.getAuthorizationServerSettings();

				String deviceAuthorizationEndpoint = UriComponentsBuilder.fromUriString(issuer)
					.path(authorizationServerSettings.getDeviceAuthorizationEndpoint())
					.build()
					.toUriString();

				builder.deviceAuthorizationEndpoint(deviceAuthorizationEndpoint);
				builder.grantType(AuthorizationGrantType.DEVICE_CODE.getValue());
			});
		}

		this.configurers.values().forEach((configurer) -> configurer.configure(httpSecurity));
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	@SuppressWarnings("unchecked")
	<T> T getConfigurer(Class<T> type) {
		return (T) this.configurers.get(type);
	}

	private <T extends AbstractOAuth2Configurer> void addConfigurer(Class<T> configurerType, T configurer) {
		this.configurers.put(configurerType, configurer);
	}

}
