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

package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.util.function.Consumer;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationServerMetadataEndpointFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Configurer for the OAuth 2.0 Authorization Server Metadata Endpoint.
 *
 * @author Joe Grandja
 * @since 0.4.0
 * @see OAuth2AuthorizationServerConfigurer#authorizationServerMetadataEndpoint
 * @see OAuth2AuthorizationServerMetadataEndpointFilter
 */
public final class OAuth2AuthorizationServerMetadataEndpointConfigurer extends AbstractOAuth2Configurer {

	private RequestMatcher requestMatcher;

	private Consumer<OAuth2AuthorizationServerMetadata.Builder> authorizationServerMetadataCustomizer;

	private Consumer<OAuth2AuthorizationServerMetadata.Builder> defaultAuthorizationServerMetadataCustomizer;

	/**
	 * Restrict for internal use only.
	 * @param objectPostProcessor an {@code ObjectPostProcessor}
	 */
	OAuth2AuthorizationServerMetadataEndpointConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * Sets the {@code Consumer} providing access to the
	 * {@link OAuth2AuthorizationServerMetadata.Builder} allowing the ability to customize
	 * the claims of the Authorization Server's configuration.
	 * @param authorizationServerMetadataCustomizer the {@code Consumer} providing access
	 * to the {@link OAuth2AuthorizationServerMetadata.Builder}
	 * @return the {@link OAuth2AuthorizationServerMetadataEndpointConfigurer} for further
	 * configuration
	 */
	public OAuth2AuthorizationServerMetadataEndpointConfigurer authorizationServerMetadataCustomizer(
			Consumer<OAuth2AuthorizationServerMetadata.Builder> authorizationServerMetadataCustomizer) {
		this.authorizationServerMetadataCustomizer = authorizationServerMetadataCustomizer;
		return this;
	}

	void addDefaultAuthorizationServerMetadataCustomizer(
			Consumer<OAuth2AuthorizationServerMetadata.Builder> defaultAuthorizationServerMetadataCustomizer) {
		this.defaultAuthorizationServerMetadataCustomizer = (this.defaultAuthorizationServerMetadataCustomizer == null)
				? defaultAuthorizationServerMetadataCustomizer : this.defaultAuthorizationServerMetadataCustomizer
					.andThen(defaultAuthorizationServerMetadataCustomizer);
	}

	@Override
	void init(HttpSecurity httpSecurity) {
		AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils
			.getAuthorizationServerSettings(httpSecurity);
		String authorizationServerMetadataEndpointUri = authorizationServerSettings.isMultipleIssuersAllowed()
				? "/.well-known/oauth-authorization-server/**" : "/.well-known/oauth-authorization-server";
		this.requestMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.GET, authorizationServerMetadataEndpointUri);
	}

	@Override
	void configure(HttpSecurity httpSecurity) {
		OAuth2AuthorizationServerMetadataEndpointFilter authorizationServerMetadataEndpointFilter = new OAuth2AuthorizationServerMetadataEndpointFilter();
		Consumer<OAuth2AuthorizationServerMetadata.Builder> authorizationServerMetadataCustomizer = getAuthorizationServerMetadataCustomizer();
		if (authorizationServerMetadataCustomizer != null) {
			authorizationServerMetadataEndpointFilter
				.setAuthorizationServerMetadataCustomizer(authorizationServerMetadataCustomizer);
		}
		httpSecurity.addFilterBefore(postProcess(authorizationServerMetadataEndpointFilter),
				AbstractPreAuthenticatedProcessingFilter.class);
	}

	private Consumer<OAuth2AuthorizationServerMetadata.Builder> getAuthorizationServerMetadataCustomizer() {
		Consumer<OAuth2AuthorizationServerMetadata.Builder> authorizationServerMetadataCustomizer = null;
		if (this.defaultAuthorizationServerMetadataCustomizer != null
				|| this.authorizationServerMetadataCustomizer != null) {
			if (this.defaultAuthorizationServerMetadataCustomizer != null) {
				authorizationServerMetadataCustomizer = this.defaultAuthorizationServerMetadataCustomizer;
			}
			if (this.authorizationServerMetadataCustomizer != null) {
				authorizationServerMetadataCustomizer = (authorizationServerMetadataCustomizer != null)
						? authorizationServerMetadataCustomizer.andThen(this.authorizationServerMetadataCustomizer)
						: this.authorizationServerMetadataCustomizer;
			}
		}
		return authorizationServerMetadataCustomizer;
	}

	@Override
	RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

}
