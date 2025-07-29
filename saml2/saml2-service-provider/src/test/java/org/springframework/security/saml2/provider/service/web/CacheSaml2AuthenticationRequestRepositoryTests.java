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

package org.springframework.security.saml2.provider.service.web;

import org.junit.jupiter.api.Test;

import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2PostAuthenticationRequests;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link CacheSaml2AuthenticationRequestRepository}
 */
class CacheSaml2AuthenticationRequestRepositoryTests {

	CacheSaml2AuthenticationRequestRepository repository = new CacheSaml2AuthenticationRequestRepository();

	@Test
	void loadAuthenticationRequestWhenCachedThenReturns() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(Saml2ParameterNames.RELAY_STATE, "test");
		Saml2PostAuthenticationRequest authenticationRequest = TestSaml2PostAuthenticationRequests.create();
		this.repository.saveAuthenticationRequest(authenticationRequest, request, null);
		assertThat(this.repository.loadAuthenticationRequest(request)).isEqualTo(authenticationRequest);
		this.repository.removeAuthenticationRequest(request, null);
		assertThat(this.repository.loadAuthenticationRequest(request)).isNull();
	}

	@Test
	void loadAuthenticationRequestWhenNoRelayStateThenException() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.repository.loadAuthenticationRequest(request));
	}

	@Test
	void saveAuthenticationRequestWhenNoRelayStateThenException() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.repository.saveAuthenticationRequest(null, request, null));
	}

	@Test
	void removeAuthenticationRequestWhenNoRelayStateThenException() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.repository.removeAuthenticationRequest(request, null));
	}

	@Test
	void repositoryWhenCustomCacheThenUses() {
		CacheSaml2AuthenticationRequestRepository repository = new CacheSaml2AuthenticationRequestRepository();
		Cache cache = spy(new ConcurrentMapCache("requests"));
		repository.setCache(cache);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(Saml2ParameterNames.RELAY_STATE, "test");
		Saml2PostAuthenticationRequest authenticationRequest = TestSaml2PostAuthenticationRequests.create();
		repository.saveAuthenticationRequest(authenticationRequest, request, null);
		verify(cache).put(eq("test"), any());
		repository.loadAuthenticationRequest(request);
		verify(cache).get("test", AbstractSaml2AuthenticationRequest.class);
		repository.removeAuthenticationRequest(request, null);
		verify(cache).evict("test");
	}

}
