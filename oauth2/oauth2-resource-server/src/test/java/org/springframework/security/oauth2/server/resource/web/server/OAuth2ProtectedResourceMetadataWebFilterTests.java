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

package org.springframework.security.oauth2.server.resource.web.server;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2ProtectedResourceMetadataWebFilter}.
 *
 * @author Andrey Litvitski
 */
public class OAuth2ProtectedResourceMetadataWebFilterTests {

	private static final String DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI = "/.well-known/oauth-protected-resource";

	private final OAuth2ProtectedResourceMetadataWebFilter filter = new OAuth2ProtectedResourceMetadataWebFilter();

	@Test
	public void setProtectedResourceMetadataCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setProtectedResourceMetadataCustomizer(null))
			.withMessage("protectedResourceMetadataCustomizer cannot be null");
	}

	@Test
	public void doFilterWhenNotProtectedResourceMetadataRequestThenNotProcessed() {
		String requestUri = "/path";
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get(requestUri));
		WebFilterChain filterChain = mock(WebFilterChain.class);
		given(filterChain.filter(exchange)).willReturn(Mono.empty());

		this.filter.filter(exchange, filterChain).block();

		verify(filterChain).filter(any(ServerWebExchange.class));
	}

	@Test
	public void doFilterWhenProtectedResourceMetadataRequestPostThenNotProcessed() {
		MockServerWebExchange exchange = MockServerWebExchange
			.from(MockServerHttpRequest.post(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI));
		WebFilterChain filterChain = mock(WebFilterChain.class);
		given(filterChain.filter(exchange)).willReturn(Mono.empty());

		this.filter.filter(exchange, filterChain).block();

		verify(filterChain).filter(any(ServerWebExchange.class));
	}

	@Test
	public void doFilterWhenProtectedResourceMetadataRequestThenMetadataResponse() {
		this.filter.setProtectedResourceMetadataCustomizer(
				(protectedResourceMetadata) -> protectedResourceMetadata.authorizationServer("https://provider1.com")
					.authorizationServer("https://provider2.com")
					.scope("scope1")
					.scope("scope2")
					.resourceName("resourceName"));

		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest
			.get("http://localhost" + DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI));
		WebFilterChain filterChain = mock(WebFilterChain.class);

		this.filter.filter(exchange, filterChain).block();

		verifyNoInteractions(filterChain);

		MockServerHttpResponse response = exchange.getResponse();
		assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
		String protectedResourceMetadataResponse = response.getBodyAsString().block();
		assertThat(protectedResourceMetadataResponse).contains("\"resource\":\"http://localhost\"");
		assertThat(protectedResourceMetadataResponse)
			.contains("\"authorization_servers\":[\"https://provider1.com\",\"https://provider2.com\"]");
		assertThat(protectedResourceMetadataResponse).contains("\"scopes_supported\":[\"scope1\",\"scope2\"]");
		assertThat(protectedResourceMetadataResponse).contains("\"bearer_methods_supported\":[\"header\"]");
		assertThat(protectedResourceMetadataResponse).contains("\"resource_name\":\"resourceName\"");
		assertThat(protectedResourceMetadataResponse).contains("\"tls_client_certificate_bound_access_tokens\":true");
	}

}
