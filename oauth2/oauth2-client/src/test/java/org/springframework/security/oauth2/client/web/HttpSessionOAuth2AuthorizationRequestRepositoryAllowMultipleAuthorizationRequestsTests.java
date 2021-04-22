/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.client.web;

import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link HttpSessionOAuth2AuthorizationRequestRepository} when
 * {@link HttpSessionOAuth2AuthorizationRequestRepository#setAllowMultipleAuthorizationRequests(boolean)}
 * is enabled.
 *
 * @author Joe Grandja
 * @author Craig Andrews
 */
public class HttpSessionOAuth2AuthorizationRequestRepositoryAllowMultipleAuthorizationRequestsTests
		extends HttpSessionOAuth2AuthorizationRequestRepositoryTests {

	@Before
	public void setup() {
		this.authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();
		this.authorizationRequestRepository.setAllowMultipleAuthorizationRequests(true);
	}

	// gh-5110
	@Test
	public void loadAuthorizationRequestWhenMultipleSavedThenReturnMatchingAuthorizationRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		String state1 = "state-1122";
		OAuth2AuthorizationRequest authorizationRequest1 = createAuthorizationRequest().state(state1).build();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest1, request, response);
		String state2 = "state-3344";
		OAuth2AuthorizationRequest authorizationRequest2 = createAuthorizationRequest().state(state2).build();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest2, request, response);
		String state3 = "state-5566";
		OAuth2AuthorizationRequest authorizationRequest3 = createAuthorizationRequest().state(state3).build();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest3, request, response);
		request.addParameter(OAuth2ParameterNames.STATE, state1);
		OAuth2AuthorizationRequest loadedAuthorizationRequest1 = this.authorizationRequestRepository
				.loadAuthorizationRequest(request);
		assertThat(loadedAuthorizationRequest1).isEqualTo(authorizationRequest1);
		request.removeParameter(OAuth2ParameterNames.STATE);
		request.addParameter(OAuth2ParameterNames.STATE, state2);
		OAuth2AuthorizationRequest loadedAuthorizationRequest2 = this.authorizationRequestRepository
				.loadAuthorizationRequest(request);
		assertThat(loadedAuthorizationRequest2).isEqualTo(authorizationRequest2);
		request.removeParameter(OAuth2ParameterNames.STATE);
		request.addParameter(OAuth2ParameterNames.STATE, state3);
		OAuth2AuthorizationRequest loadedAuthorizationRequest3 = this.authorizationRequestRepository
				.loadAuthorizationRequest(request);
		assertThat(loadedAuthorizationRequest3).isEqualTo(authorizationRequest3);
	}

}
