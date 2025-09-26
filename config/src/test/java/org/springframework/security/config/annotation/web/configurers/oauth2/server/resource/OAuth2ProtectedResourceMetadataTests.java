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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.resource;

import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadata;
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadataClaimNames;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for OAuth 2.0 Protected Resource Metadata Requests.
 *
 * @author Joe Grandja
 */
@ExtendWith(SpringTestContextExtension.class)
public class OAuth2ProtectedResourceMetadataTests {

	private static final String DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI = "/.well-known/oauth-protected-resource";

	private static final String RESOURCE = "https://resource.com:8443";

	private static final String ISSUER_1 = "https://provider1.com";

	private static final String ISSUER_2 = "https://provider2.com";

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestWhenProtectedResourceMetadataRequestThenReturnMetadataResponse() throws Exception {
		this.spring.register(ResourceServerConfiguration.class).autowire();

		this.mvc.perform(get(RESOURCE.concat(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI)))
			.andExpect(status().is2xxSuccessful())
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE).value(RESOURCE))
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED).isArray())
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED).value(hasSize(1)))
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED)
				.value(hasItem("header")))
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS)
				.value(true))
			.andReturn();
	}

	@Test
	public void requestWhenProtectedResourceMetadataRequestIncludesResourcePathThenMetadataResponseHasResourcePath()
			throws Exception {
		this.spring.register(ResourceServerConfiguration.class).autowire();

		String host = RESOURCE;

		String resourcePath = "/resource1";
		String resource = host.concat(resourcePath);
		this.mvc.perform(get(host.concat(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI).concat(resourcePath)))
			.andExpect(status().is2xxSuccessful())
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE).value(resource))
			.andReturn();

		resourcePath = "/path1/resource2";
		resource = host.concat(resourcePath);
		this.mvc.perform(get(host.concat(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI).concat(resourcePath)))
			.andExpect(status().is2xxSuccessful())
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE).value(resource))
			.andReturn();

		resourcePath = "/path1/path2/resource3";
		resource = host.concat(resourcePath);
		this.mvc.perform(get(host.concat(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI).concat(resourcePath)))
			.andExpect(status().is2xxSuccessful())
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE).value(resource))
			.andReturn();
	}

	@Test
	public void requestWhenProtectedResourceMetadataRequestAndMetadataCustomizerSetThenReturnCustomMetadataResponse()
			throws Exception {
		this.spring.register(ResourceServerConfigurationWithMetadataCustomizer.class).autowire();

		this.mvc.perform(get(RESOURCE.concat(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI)))
			.andExpect(status().is2xxSuccessful())
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE).value(RESOURCE))
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS).isArray())
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS).value(hasSize(2)))
			.andExpect(
					jsonPath(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS).value(hasItem(ISSUER_1)))
			.andExpect(
					jsonPath(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS).value(hasItem(ISSUER_2)))
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED).isArray())
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED).value(hasSize(2)))
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED).value(hasItem("scope1")))
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED).value(hasItem("scope2")))
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED).isArray())
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED).value(hasSize(1)))
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED)
				.value(hasItem("header")))
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE_NAME).value("resourceName"))
			.andExpect(jsonPath(OAuth2ProtectedResourceMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS)
				.value(true))
			.andReturn();
	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class ResourceServerConfiguration {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) ->
					authorize
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer((oauth2) ->
					oauth2
						.jwt(Customizer.withDefaults())
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		JwtDecoder jwtDecoder() {
			return NimbusJwtDecoder.withPublicKey(TestKeys.DEFAULT_PUBLIC_KEY).build();
		}

	}

	@EnableWebSecurity
	@Configuration(proxyBeanMethods = false)
	static class ResourceServerConfigurationWithMetadataCustomizer extends ResourceServerConfiguration {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) ->
					authorize
						.anyRequest().authenticated()
				)
				.oauth2ResourceServer((oauth2) ->
					oauth2
						.jwt(Customizer.withDefaults())
						.protectedResourceMetadata((metadata) ->
							metadata.protectedResourceMetadataCustomizer(protectedResourceMetadataCustomizer())
						)
				);
			// @formatter:on
			return http.build();
		}

		private Consumer<OAuth2ProtectedResourceMetadata.Builder> protectedResourceMetadataCustomizer() {
			return (protectedResourceMetadata) -> protectedResourceMetadata.authorizationServer(ISSUER_1)
				.authorizationServer(ISSUER_2)
				.scope("scope1")
				.scope("scope2")
				.resourceName("resourceName");
		}

	}

}
