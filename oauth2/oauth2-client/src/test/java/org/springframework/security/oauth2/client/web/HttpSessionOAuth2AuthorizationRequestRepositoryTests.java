/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.web;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link HttpSessionOAuth2AuthorizationRequestRepository}.
 *
 * @author Joe Grandja
 */
@PrepareForTest(OAuth2AuthorizationRequest.class)
@RunWith(PowerMockRunner.class)
public class HttpSessionOAuth2AuthorizationRequestRepositoryTests {
	private HttpSessionOAuth2AuthorizationRequestRepository authorizationRequestRepository =
		new HttpSessionOAuth2AuthorizationRequestRepository();

	@Test(expected = IllegalArgumentException.class)
	public void loadAuthorizationRequestWhenHttpServletRequestIsNullThenThrowIllegalArgumentException() {
		this.authorizationRequestRepository.loadAuthorizationRequest(null);
	}

	@Test
	public void loadAuthorizationRequestWhenNotSavedThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.STATE, "state-1234");
		OAuth2AuthorizationRequest authorizationRequest =
			this.authorizationRequestRepository.loadAuthorizationRequest(request);

		assertThat(authorizationRequest).isNull();
	}

	@Test
	public void loadAuthorizationRequestWhenSavedThenReturnAuthorizationRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authorizationRequest = mock(OAuth2AuthorizationRequest.class);
		when(authorizationRequest.getState()).thenReturn("state-1234");

		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
		request.addParameter(OAuth2ParameterNames.STATE, "state-1234");
		OAuth2AuthorizationRequest loadedAuthorizationRequest =
			this.authorizationRequestRepository.loadAuthorizationRequest(request);

		assertThat(loadedAuthorizationRequest).isEqualTo(authorizationRequest);
	}

	// gh-5110
	@Test
	public void loadAuthorizationRequestWhenMultipleSavedThenReturnMatchingAuthorizationRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		String state1 = "state-1122";
		OAuth2AuthorizationRequest authorizationRequest1 = mock(OAuth2AuthorizationRequest.class);
		when(authorizationRequest1.getState()).thenReturn(state1);
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest1, request, response);

		String state2 = "state-3344";
		OAuth2AuthorizationRequest authorizationRequest2 = mock(OAuth2AuthorizationRequest.class);
		when(authorizationRequest2.getState()).thenReturn(state2);
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest2, request, response);

		String state3 = "state-5566";
		OAuth2AuthorizationRequest authorizationRequest3 = mock(OAuth2AuthorizationRequest.class);
		when(authorizationRequest3.getState()).thenReturn(state3);
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest3, request, response);

		request.addParameter(OAuth2ParameterNames.STATE, state1);
		OAuth2AuthorizationRequest loadedAuthorizationRequest1 =
			this.authorizationRequestRepository.loadAuthorizationRequest(request);
		assertThat(loadedAuthorizationRequest1).isEqualTo(authorizationRequest1);

		request.removeParameter(OAuth2ParameterNames.STATE);
		request.addParameter(OAuth2ParameterNames.STATE, state2);
		OAuth2AuthorizationRequest loadedAuthorizationRequest2 =
			this.authorizationRequestRepository.loadAuthorizationRequest(request);
		assertThat(loadedAuthorizationRequest2).isEqualTo(authorizationRequest2);

		request.removeParameter(OAuth2ParameterNames.STATE);
		request.addParameter(OAuth2ParameterNames.STATE, state3);
		OAuth2AuthorizationRequest loadedAuthorizationRequest3 =
			this.authorizationRequestRepository.loadAuthorizationRequest(request);
		assertThat(loadedAuthorizationRequest3).isEqualTo(authorizationRequest3);
	}

	@Test(expected = IllegalArgumentException.class)
	public void loadAuthorizationRequestWhenSavedAndStateParameterNullThenThrowIllegalArgumentException() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		OAuth2AuthorizationRequest authorizationRequest = mock(OAuth2AuthorizationRequest.class);
		when(authorizationRequest.getState()).thenReturn("state-1234");
		this.authorizationRequestRepository.saveAuthorizationRequest(
			authorizationRequest, request, new MockHttpServletResponse());

		this.authorizationRequestRepository.loadAuthorizationRequest(request);
	}

	@Test(expected = IllegalArgumentException.class)
	public void saveAuthorizationRequestWhenHttpServletRequestIsNullThenThrowIllegalArgumentException() {
		this.authorizationRequestRepository.saveAuthorizationRequest(
			mock(OAuth2AuthorizationRequest.class), null, new MockHttpServletResponse());
	}

	@Test(expected = IllegalArgumentException.class)
	public void saveAuthorizationRequestWhenHttpServletResponseIsNullThenThrowIllegalArgumentException() {
		this.authorizationRequestRepository.saveAuthorizationRequest(
			mock(OAuth2AuthorizationRequest.class), new MockHttpServletRequest(), null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void saveAuthorizationRequestWhenStateNullThenThrowIllegalArgumentException() {
		this.authorizationRequestRepository.saveAuthorizationRequest(
			mock(OAuth2AuthorizationRequest.class), new MockHttpServletRequest(), new MockHttpServletResponse());
	}

	@Test
	public void saveAuthorizationRequestWhenNotNullThenSaved() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		OAuth2AuthorizationRequest authorizationRequest = mock(OAuth2AuthorizationRequest.class);
		when(authorizationRequest.getState()).thenReturn("state-1234");
		this.authorizationRequestRepository.saveAuthorizationRequest(
			authorizationRequest, request, new MockHttpServletResponse());

		request.addParameter(OAuth2ParameterNames.STATE, "state-1234");
		OAuth2AuthorizationRequest loadedAuthorizationRequest =
			this.authorizationRequestRepository.loadAuthorizationRequest(request);

		assertThat(loadedAuthorizationRequest).isEqualTo(authorizationRequest);
	}

	@Test
	public void saveAuthorizationRequestWhenNullThenRemoved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authorizationRequest = mock(OAuth2AuthorizationRequest.class);
		when(authorizationRequest.getState()).thenReturn("state-1234");

		this.authorizationRequestRepository.saveAuthorizationRequest(		// Save
			authorizationRequest, request, response);

		request.addParameter(OAuth2ParameterNames.STATE, "state-1234");
		this.authorizationRequestRepository.saveAuthorizationRequest(		// Null value removes
			null, request, response);

		OAuth2AuthorizationRequest loadedAuthorizationRequest =
			this.authorizationRequestRepository.loadAuthorizationRequest(request);

		assertThat(loadedAuthorizationRequest).isNull();
	}

	@Test(expected = IllegalArgumentException.class)
	public void removeAuthorizationRequestWhenHttpServletRequestIsNullThenThrowIllegalArgumentException() {
		this.authorizationRequestRepository.removeAuthorizationRequest(null);
	}

	@Test
	public void removeAuthorizationRequestWhenSavedThenRemoved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authorizationRequest = mock(OAuth2AuthorizationRequest.class);
		when(authorizationRequest.getState()).thenReturn("state-1234");

		this.authorizationRequestRepository.saveAuthorizationRequest(
			authorizationRequest, request, response);

		request.addParameter(OAuth2ParameterNames.STATE, "state-1234");
		OAuth2AuthorizationRequest removedAuthorizationRequest =
			this.authorizationRequestRepository.removeAuthorizationRequest(request);
		OAuth2AuthorizationRequest loadedAuthorizationRequest =
			this.authorizationRequestRepository.loadAuthorizationRequest(request);

		assertThat(removedAuthorizationRequest).isNotNull();
		assertThat(loadedAuthorizationRequest).isNull();
	}

	@Test
	public void removeAuthorizationRequestWhenNotSavedThenNotRemoved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.STATE, "state-1234");

		OAuth2AuthorizationRequest removedAuthorizationRequest =
			this.authorizationRequestRepository.removeAuthorizationRequest(request);

		assertThat(removedAuthorizationRequest).isNull();
	}
}
