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

package org.springframework.security.oauth2.server.resource.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link OAuth2ProtectedResourceMetadataFilter}.
 *
 * @author Joe Grandja
 */
public class OAuth2ProtectedResourceMetadataFilterTests {

	private static final String DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI = "/.well-known/oauth-protected-resource";

	private final OAuth2ProtectedResourceMetadataFilter filter = new OAuth2ProtectedResourceMetadataFilter();

	@Test
	public void setProtectedResourceMetadataCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.filter.setProtectedResourceMetadataCustomizer(null))
			.withMessage("protectedResourceMetadataCustomizer cannot be null");
	}

	@Test
	public void doFilterWhenNotProtectedResourceMetadataRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenProtectedResourceMetadataRequestPostThenNotProcessed() throws Exception {
		String requestUri = DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenProtectedResourceMetadataRequestThenMetadataResponse() throws Exception {
		this.filter.setProtectedResourceMetadataCustomizer(
				(protectedResourceMetadata) -> protectedResourceMetadata.authorizationServer("https://provider1.com")
					.authorizationServer("https://provider2.com")
					.scope("scope1")
					.scope("scope2")
					.resourceName("resourceName"));

		String requestUri = DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		String protectedResourceMetadataResponse = response.getContentAsString();
		assertThat(protectedResourceMetadataResponse).contains("\"resource\":\"http://localhost\"");
		assertThat(protectedResourceMetadataResponse)
			.contains("\"authorization_servers\":[\"https://provider1.com\",\"https://provider2.com\"]");
		assertThat(protectedResourceMetadataResponse).contains("\"scopes_supported\":[\"scope1\",\"scope2\"]");
		assertThat(protectedResourceMetadataResponse).contains("\"bearer_methods_supported\":[\"header\"]");
		assertThat(protectedResourceMetadataResponse).contains("\"resource_name\":\"resourceName\"");
		assertThat(protectedResourceMetadataResponse).contains("\"tls_client_certificate_bound_access_tokens\":true");
	}

}
