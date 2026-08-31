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

package org.springframework.security.config.web.server;

import java.util.List;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadata;
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadataClaimNames;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.config.EnableWebFlux;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for OAuth 2.0 Protected Resource Metadata Requests.
 *
 * @author Andrey Litvitski
 */
@ExtendWith(SpringTestContextExtension.class)
public class OAuth2ProtectedResourceMetadataTests {

	private static final String DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI = "/.well-known/oauth-protected-resource";

	private static final String RESOURCE = "https://resource.com:8443";

	private static final String ISSUER_1 = "https://provider1.com";

	private static final String ISSUER_2 = "https://provider2.com";

	public final SpringTestContext spring = new SpringTestContext(this);

	private WebTestClient client;

	@Autowired
	public void setApplicationContext(ApplicationContext context) {
		this.client = WebTestClient.bindToApplicationContext(context).build();
	}

	@Test
	public void requestWhenProtectedResourceMetadataRequestThenReturnMetadataResponse() {
		this.spring.register(ResourceServerConfiguration.class).autowire();

		this.client.get()
			.uri(RESOURCE.concat(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI))
			.exchange()
			.expectStatus()
			.is2xxSuccessful()
			.expectBody()
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE)
			.isEqualTo(RESOURCE)
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED)
			.isArray()
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED)
			.value((List<Object> values) -> assertThat(values).hasSize(1).contains("header"))
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS)
			.isEqualTo(true);
	}

	@Test
	public void requestWhenProtectedResourceMetadataRequestIncludesResourcePathThenMetadataResponseHasResourcePath() {
		this.spring.register(ResourceServerConfiguration.class).autowire();

		String host = RESOURCE;

		String resourcePath = "/resource1";
		String resource = host.concat(resourcePath);
		this.client.get()
			.uri(host.concat(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI).concat(resourcePath))
			.exchange()
			.expectStatus()
			.is2xxSuccessful()
			.expectBody()
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE)
			.isEqualTo(resource);

		resourcePath = "/path1/resource2";
		resource = host.concat(resourcePath);
		this.client.get()
			.uri(host.concat(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI).concat(resourcePath))
			.exchange()
			.expectStatus()
			.is2xxSuccessful()
			.expectBody()
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE)
			.isEqualTo(resource);

		resourcePath = "/path1/path2/resource3";
		resource = host.concat(resourcePath);
		this.client.get()
			.uri(host.concat(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI).concat(resourcePath))
			.exchange()
			.expectStatus()
			.is2xxSuccessful()
			.expectBody()
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE)
			.isEqualTo(resource);
	}

	@Test
	public void requestWhenProtectedResourceMetadataRequestAndMetadataCustomizerSetThenReturnCustomMetadataResponse() {
		this.spring.register(ResourceServerConfigurationWithMetadataCustomizer.class).autowire();

		this.client.get()
			.uri(RESOURCE.concat(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI))
			.exchange()
			.expectStatus()
			.is2xxSuccessful()
			.expectBody()
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE)
			.isEqualTo(RESOURCE)
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS)
			.isArray()
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS)
			.value((List<Object> values) -> assertThat(values).hasSize(2).contains(ISSUER_1, ISSUER_2))
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED)
			.isArray()
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED)
			.value((List<Object> values) -> assertThat(values).hasSize(2).contains("scope1", "scope2"))
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED)
			.isArray()
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED)
			.value((List<Object> values) -> assertThat(values).hasSize(1).contains("header"))
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE_NAME)
			.isEqualTo("resourceName")
			.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS)
			.isEqualTo(true);
	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class ResourceServerConfiguration {

		@Bean
		SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize
					.anyExchange().authenticated()
				)
				.oauth2ResourceServer((oauth2) -> oauth2
					.jwt(Customizer.withDefaults())
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		ReactiveJwtDecoder jwtDecoder() {
			return NimbusReactiveJwtDecoder.withPublicKey(TestKeys.DEFAULT_PUBLIC_KEY).build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebFlux
	@EnableWebFluxSecurity
	static class ResourceServerConfigurationWithMetadataCustomizer extends ResourceServerConfiguration {

		@Bean
		SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
			// @formatter:off
			http
				.authorizeExchange((authorize) -> authorize
					.anyExchange().authenticated()
				)
				.oauth2ResourceServer((oauth2) -> oauth2
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
