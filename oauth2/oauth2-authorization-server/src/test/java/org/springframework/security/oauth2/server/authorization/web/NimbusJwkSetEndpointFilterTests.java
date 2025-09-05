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

package org.springframework.security.oauth2.server.authorization.web;

import java.util.ArrayList;
import java.util.List;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.jose.TestJwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link NimbusJwkSetEndpointFilter}.
 *
 * @author Joe Grandja
 */
public class NimbusJwkSetEndpointFilterTests {

	private static final String DEFAULT_JWK_SET_ENDPOINT_URI = "/oauth2/jwks";

	private List<JWK> jwkList;

	private JWKSource<SecurityContext> jwkSource;

	private NimbusJwkSetEndpointFilter filter;

	@BeforeEach
	public void setUp() {
		this.jwkList = new ArrayList<>();
		this.jwkSource = (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(this.jwkList));
		this.filter = new NimbusJwkSetEndpointFilter(this.jwkSource);
	}

	@Test
	public void constructorWhenJwkSourceNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> new NimbusJwkSetEndpointFilter(null))
			.withMessage("jwkSource cannot be null");
	}

	@Test
	public void constructorWhenJwkSetEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new NimbusJwkSetEndpointFilter(this.jwkSource, null))
			.withMessage("jwkSetEndpointUri cannot be empty");
	}

	@Test
	public void doFilterWhenNotJwkSetRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenJwkSetRequestPostThenNotProcessed() throws Exception {
		String requestUri = DEFAULT_JWK_SET_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAsymmetricKeysThenJwkSetResponse() throws Exception {
		RSAKey rsaJwk = TestJwks.DEFAULT_RSA_JWK;
		this.jwkList.add(rsaJwk);
		ECKey ecJwk = TestJwks.DEFAULT_EC_JWK;
		this.jwkList.add(ecJwk);

		String requestUri = DEFAULT_JWK_SET_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);

		JWKSet jwkSet = JWKSet.parse(response.getContentAsString());
		assertThat(jwkSet.getKeys()).hasSize(2);

		RSAKey rsaJwkResult = (RSAKey) jwkSet.getKeyByKeyId(rsaJwk.getKeyID());
		assertThat(rsaJwkResult).isNotNull();
		assertThat(rsaJwkResult.toRSAPublicKey()).isEqualTo(rsaJwk.toRSAPublicKey());
		assertThat(rsaJwkResult.toRSAPrivateKey()).isNull();
		assertThat(rsaJwkResult.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);

		ECKey ecJwkResult = (ECKey) jwkSet.getKeyByKeyId(ecJwk.getKeyID());
		assertThat(ecJwkResult).isNotNull();
		assertThat(ecJwkResult.toECPublicKey()).isEqualTo(ecJwk.toECPublicKey());
		assertThat(ecJwkResult.toECPrivateKey()).isNull();
		assertThat(ecJwkResult.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
	}

	@Test
	public void doFilterWhenSymmetricKeysThenJwkSetResponseEmpty() throws Exception {
		OctetSequenceKey secretJwk = TestJwks.DEFAULT_SECRET_JWK;
		this.jwkList.add(secretJwk);

		String requestUri = DEFAULT_JWK_SET_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);

		JWKSet jwkSet = JWKSet.parse(response.getContentAsString());
		assertThat(jwkSet.getKeys()).isEmpty();
	}

}
