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
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link HttpSessionOAuth2AuthorizationRequestRepository}.
 *
 * @author Joe Grandja
 */
@RunWith(MockitoJUnitRunner.class)
public class HttpSessionOAuth2AuthorizationRequestRepositoryTests {
	private HttpSessionOAuth2AuthorizationRequestRepository authorizationRequestRepository =
			new HttpSessionOAuth2AuthorizationRequestRepository();
	private ClientRegistration registration = ClientRegistration.withRegistrationId("registration-1")
			.clientId("client-1")
			.clientSecret("secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
			.scope("user")
			.authorizationUri("https://provider.com/oauth2/authorize")
			.tokenUri("https://provider.com/oauth2/token")
			.userInfoUri("https://provider.com/oauth2/user")
			.userNameAttributeName("id")
			.clientName("client-1")
			.build();

	@Test(expected = IllegalArgumentException.class)
	public void removeAuthorizationRequestWhenClientRegistrationIsNullThenThrowIllegalArgumentException() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.STATE, "state-1234");
		this.authorizationRequestRepository.removeAuthorizationRequest(request, null);
	}

	@Test
	public void removeAuthorizationRequestWhenNotSavedThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.STATE, "state-1234");
		OAuth2AuthorizationRequest authorizationRequest =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);

		assertThat(authorizationRequest).isNull();
	}

	@Test
	public void removeAuthorizationRequestWhenSavedThenReturnAuthorizationRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authorizationRequest = createAuthorizationRequest().build();

		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response, registration);
		request.addParameter(OAuth2ParameterNames.STATE, authorizationRequest.getState());
		OAuth2AuthorizationRequest loadedAuthorizationRequest =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);

		assertThat(loadedAuthorizationRequest).isEqualTo(authorizationRequest);
	}

	// gh-5110
	@Test
	public void removeAuthorizationRequestWhenMultipleSavedThenReturnMatchingAuthorizationRequest() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		String state1 = "state-1122";
		OAuth2AuthorizationRequest authorizationRequest1 = createAuthorizationRequest().state(state1).build();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest1, request, response, registration);

		String state2 = "state-3344";
		OAuth2AuthorizationRequest authorizationRequest2 = createAuthorizationRequest().state(state2).build();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest2, request, response, registration);

		String state3 = "state-5566";
		OAuth2AuthorizationRequest authorizationRequest3 = createAuthorizationRequest().state(state3).build();
		this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest3, request, response, registration);

		request.addParameter(OAuth2ParameterNames.STATE, state1);
		OAuth2AuthorizationRequest loadedAuthorizationRequest1 =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);
		assertThat(loadedAuthorizationRequest1).isEqualTo(authorizationRequest1);

		request.removeParameter(OAuth2ParameterNames.STATE);
		request.addParameter(OAuth2ParameterNames.STATE, state2);
		OAuth2AuthorizationRequest loadedAuthorizationRequest2 =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);
		assertThat(loadedAuthorizationRequest2).isEqualTo(authorizationRequest2);

		request.removeParameter(OAuth2ParameterNames.STATE);
		request.addParameter(OAuth2ParameterNames.STATE, state3);
		OAuth2AuthorizationRequest loadedAuthorizationRequest3 =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);
		assertThat(loadedAuthorizationRequest3).isEqualTo(authorizationRequest3);
	}

	@Test
	public void removeAuthorizationRequestWhenSavedAndStateParameterNullThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		OAuth2AuthorizationRequest authorizationRequest = createAuthorizationRequest().build();
		this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest, request, new MockHttpServletResponse(), registration);

		assertThat(this.authorizationRequestRepository.removeAuthorizationRequest(request, registration)).isNull();
	}

	@Test
	public void saveAuthorizationRequestWhenHttpServletRequestIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationRequest authorizationRequest = createAuthorizationRequest().build();

		assertThatThrownBy(() -> this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest, null, new MockHttpServletResponse(), registration))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveAuthorizationRequestWhenHttpServletResponseIsNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationRequest authorizationRequest = createAuthorizationRequest().build();

		assertThatThrownBy(() -> this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest, new MockHttpServletRequest(), null, registration))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveAuthorizationRequestWhenStateNullThenThrowIllegalArgumentException() {
		OAuth2AuthorizationRequest authorizationRequest = createAuthorizationRequest()
				.state(null)
				.build();
		assertThatThrownBy(() -> this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest, new MockHttpServletRequest(), new MockHttpServletResponse(), registration))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void saveAuthorizationRequestWhenNotNullThenSaved() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		OAuth2AuthorizationRequest authorizationRequest = createAuthorizationRequest().build();
		this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest, request, new MockHttpServletResponse(), registration);

		request.addParameter(OAuth2ParameterNames.STATE, authorizationRequest.getState());
		OAuth2AuthorizationRequest loadedAuthorizationRequest =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);

		assertThat(loadedAuthorizationRequest).isEqualTo(authorizationRequest);
	}

	@Test
	public void saveAuthorizationRequestWhenNoExistingSessionAndDistributedSessionThenSaved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setSession(new MockDistributedHttpSession());

		OAuth2AuthorizationRequest authorizationRequest = createAuthorizationRequest().build();
		this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest, request, new MockHttpServletResponse(), registration);

		request.addParameter(OAuth2ParameterNames.STATE, authorizationRequest.getState());
		OAuth2AuthorizationRequest loadedAuthorizationRequest =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);

		assertThat(loadedAuthorizationRequest).isEqualTo(authorizationRequest);
	}

	@Test
	public void saveAuthorizationRequestWhenExistingSessionAndDistributedSessionThenSaved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setSession(new MockDistributedHttpSession());

		OAuth2AuthorizationRequest authorizationRequest1 = createAuthorizationRequest().build();
		this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest1, request, new MockHttpServletResponse(), registration);

		OAuth2AuthorizationRequest authorizationRequest2 = createAuthorizationRequest().build();
		this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest2, request, new MockHttpServletResponse(), registration);

		request.addParameter(OAuth2ParameterNames.STATE, authorizationRequest2.getState());
		OAuth2AuthorizationRequest loadedAuthorizationRequest =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);

		assertThat(loadedAuthorizationRequest).isEqualTo(authorizationRequest2);
	}

	@Test
	public void saveAuthorizationRequestWhenNullThenRemoved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();


		OAuth2AuthorizationRequest authorizationRequest = createAuthorizationRequest().build();

		this.authorizationRequestRepository.saveAuthorizationRequest(        // Save
				authorizationRequest, request, response, registration);

		request.addParameter(OAuth2ParameterNames.STATE, authorizationRequest.getState());
		this.authorizationRequestRepository.saveAuthorizationRequest(        // Null value removes
				null, request, response, registration);

		OAuth2AuthorizationRequest loadedAuthorizationRequest =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);

		assertThat(loadedAuthorizationRequest).isNull();
	}

	@Test(expected = IllegalArgumentException.class)
	public void removeAuthorizationRequestWhenHttpServletRequestIsNullThenThrowIllegalArgumentException() {
		this.authorizationRequestRepository.removeAuthorizationRequest(null, registration);
	}

	@Test
	public void removeAuthorizationRequestWhenSavedThenRemoved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authorizationRequest = createAuthorizationRequest().build();

		this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest, request, response, registration);

		request.addParameter(OAuth2ParameterNames.STATE, authorizationRequest.getState());
		OAuth2AuthorizationRequest removedAuthorizationRequest =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);
		OAuth2AuthorizationRequest loadedAuthorizationRequest =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);

		assertThat(removedAuthorizationRequest).isNotNull();
		assertThat(loadedAuthorizationRequest).isNull();
	}

	// gh-5263
	@Test
	public void removeAuthorizationRequestWhenSavedThenRemovedFromSession() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authorizationRequest = createAuthorizationRequest().build();

		this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest, request, response, registration);

		request.addParameter(OAuth2ParameterNames.STATE, authorizationRequest.getState());
		OAuth2AuthorizationRequest removedAuthorizationRequest =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);

		String sessionAttributeName = HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +
				".AUTHORIZATION_REQUEST";

		assertThat(removedAuthorizationRequest).isNotNull();
		assertThat(request.getSession().getAttribute(sessionAttributeName)).isNull();
	}

	@Test
	public void removeAuthorizationRequestWhenNotSavedThenNotRemoved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter(OAuth2ParameterNames.STATE, "state-1234");

		OAuth2AuthorizationRequest removedAuthorizationRequest =
				this.authorizationRequestRepository.removeAuthorizationRequest(request, registration);

		assertThat(removedAuthorizationRequest).isNull();
	}

	private OAuth2AuthorizationRequest.Builder createAuthorizationRequest() {
		return OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://example.com/oauth2/authorize")
				.clientId("client-id-1234")
				.state("state-1234");
	}

	static class MockDistributedHttpSession extends MockHttpSession {
		@Override
		public Object getAttribute(String name) {
			return wrap(super.getAttribute(name));
		}

		@Override
		public void setAttribute(String name, Object value) {
			super.setAttribute(name, wrap(value));
		}

		private Object wrap(Object object) {
			if (object instanceof Map) {
				object = new HashMap<>((Map<Object, Object>) object);
			}
			return object;
		}
	}
}
