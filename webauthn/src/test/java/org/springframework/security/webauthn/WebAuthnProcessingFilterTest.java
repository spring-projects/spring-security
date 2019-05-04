/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn;

import com.webauthn4j.data.extension.client.FIDOAppIDExtensionClientInput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;
import org.springframework.security.webauthn.server.ServerPropertyProvider;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Test for WebAuthnProcessingFilter
 */
public class WebAuthnProcessingFilterTest {

	@Rule
	public MockitoRule mockito = MockitoJUnit.rule();

	private ServerPropertyProvider serverPropertyProvider;
	private AuthenticationManager authenticationManager;
	private MockHttpServletRequest mockHttpServletRequest;
	private MockHttpServletResponse mockHttpServletResponse;

	@Spy
	private WebAuthnProcessingFilter target;

	private ArgumentCaptor<Authentication> captor = ArgumentCaptor.forClass(Authentication.class);

	@Before
	public void setup() {
		serverPropertyProvider = mock(ServerPropertyProvider.class);
		authenticationManager = mock(AuthenticationManager.class);
		mockHttpServletRequest = new MockHttpServletRequest();
		mockHttpServletResponse = new MockHttpServletResponse();

		target.setAuthenticationManager(authenticationManager);
		target.setServerPropertyProvider(serverPropertyProvider);
	}

	@Test
	public void attemptAuthentication_test_with_username_password() {

		mockHttpServletRequest.setMethod("POST");
		mockHttpServletRequest.setParameter("username", "username");
		mockHttpServletRequest.setParameter("password", "password");

		when(authenticationManager.authenticate(captor.capture())).thenReturn(null);
		target.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);

		Authentication authenticationToken = captor.getValue();
		assertThat(authenticationToken.getPrincipal()).isEqualTo("username");
		assertThat(authenticationToken.getCredentials()).isEqualTo("password");

	}

	@Test
	public void attemptAuthentication_test_with_credential() {

		String credentialId = "AAhdofeLeQWG6Y6gwwytZKNCDFB1WaIgqDsOwVYR5UavKQhAti4ic9_Dz-_CQEPpN0To6hiDRSCvmFHXaG6HK5yvvhm4DJRVJXzSvZiq5NefbXSYIr2uUaKbsoBe1lulhNdL9dRt6Dkkp38uq02YIR5CDaoxD-HQgMsS667aWlhHVKE884Sq0d1VVgGTDb1ds-Py_H7CDqk9SDErb8-XtQ9L";
		String clientDataJSON = "eyJjaGFsbGVuZ2UiOiJGT3JHWklmSFJfeURaSklydTVPdXBBIiwiaGFzaEFsZyI6IlMyNTYiLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ";
		String authenticatorData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaQ";
		String signature = "MEUCIGBYMUVg2KkMG7V7UEsGxUeKVaO8x587JyVoZkk6FmsgAiEA5XRKxlYe2Vpwn-JYEJhcEVJ3-0nYFG-JfheOk4rA3dc";
		String clientExtensionsJSON = "";

		ServerProperty serverProperty = mock(ServerProperty.class);


		//Given
		mockHttpServletRequest.setMethod("POST");
		mockHttpServletRequest.setServerName("example.com");
		mockHttpServletRequest.setParameter("credentialId", credentialId);
		mockHttpServletRequest.setParameter("clientDataJSON", clientDataJSON);
		mockHttpServletRequest.setParameter("authenticatorData", authenticatorData);
		mockHttpServletRequest.setParameter("signature", signature);
		mockHttpServletRequest.setParameter("clientExtensionsJSON", clientExtensionsJSON);

		when(authenticationManager.authenticate(captor.capture())).thenReturn(null);
		when(serverPropertyProvider.provide(any())).thenReturn(serverProperty);

		//When
		target.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);

		//Then
		WebAuthnAssertionAuthenticationToken authenticationToken = (WebAuthnAssertionAuthenticationToken) captor.getValue();
		verify(serverPropertyProvider).provide(mockHttpServletRequest);
		assertThat(authenticationToken.getPrincipal()).isNull();
		assertThat(authenticationToken.getCredentials()).isInstanceOf(WebAuthnAuthenticationRequest.class);
		assertThat(authenticationToken.getCredentials().getCredentialId()).isEqualTo(Base64UrlUtil.decode(credentialId));
		assertThat(authenticationToken.getCredentials().getClientDataJSON()).isEqualTo(Base64UrlUtil.decode(clientDataJSON));
		assertThat(authenticationToken.getCredentials().getAuthenticatorData()).isEqualTo(Base64UrlUtil.decode(authenticatorData));
		assertThat(authenticationToken.getCredentials().getSignature()).isEqualTo(Base64UrlUtil.decode(signature));
		assertThat(authenticationToken.getCredentials().getClientExtensionsJSON()).isEqualTo(clientExtensionsJSON);
		assertThat(authenticationToken.getCredentials().getServerProperty()).isEqualTo(serverProperty);

	}

	@Test
	public void attemptAuthentication_test_with_get_method() {

		String credentialId = "AAhdofeLeQWG6Y6gwwytZKNCDFB1WaIgqDsOwVYR5UavKQhAti4ic9_Dz-_CQEPpN0To6hiDRSCvmFHXaG6HK5yvvhm4DJRVJXzSvZiq5NefbXSYIr2uUaKbsoBe1lulhNdL9dRt6Dkkp38uq02YIR5CDaoxD-HQgMsS667aWlhHVKE884Sq0d1VVgGTDb1ds-Py_H7CDqk9SDErb8-XtQ9L";
		String clientDataJSON = "eyJjaGFsbGVuZ2UiOiJGT3JHWklmSFJfeURaSklydTVPdXBBIiwiaGFzaEFsZyI6IlMyNTYiLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ";
		String authenticatorData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaQ";
		String signature = "MEUCIGBYMUVg2KkMG7V7UEsGxUeKVaO8x587JyVoZkk6FmsgAiEA5XRKxlYe2Vpwn-JYEJhcEVJ3-0nYFG-JfheOk4rA3dc";
		String clientExtensionsJSON = "";

		ServerProperty serverProperty = mock(ServerProperty.class);

		//Given
		target.setPostOnly(false);
		mockHttpServletRequest.setMethod("GET");
		mockHttpServletRequest.setServerName("example.com");
		mockHttpServletRequest.setParameter("credentialId", credentialId);
		mockHttpServletRequest.setParameter("clientDataJSON", clientDataJSON);
		mockHttpServletRequest.setParameter("authenticatorData", authenticatorData);
		mockHttpServletRequest.setParameter("signature", signature);
		mockHttpServletRequest.setParameter("clientExtensionsJSON", clientExtensionsJSON);

		when(authenticationManager.authenticate(captor.capture())).thenReturn(null);
		when(serverPropertyProvider.provide(any())).thenReturn(serverProperty);

		//When
		target.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);

		//Then
		WebAuthnAssertionAuthenticationToken authenticationToken = (WebAuthnAssertionAuthenticationToken) captor.getValue();
		verify(serverPropertyProvider).provide(mockHttpServletRequest);
		assertThat(authenticationToken.getPrincipal()).isNull();
		assertThat(authenticationToken.getCredentials()).isInstanceOf(WebAuthnAuthenticationRequest.class);
		assertThat(authenticationToken.getCredentials().getCredentialId()).isEqualTo(Base64UrlUtil.decode(credentialId));
		assertThat(authenticationToken.getCredentials().getClientDataJSON()).isEqualTo(Base64UrlUtil.decode(clientDataJSON));
		assertThat(authenticationToken.getCredentials().getAuthenticatorData()).isEqualTo(Base64UrlUtil.decode(authenticatorData));
		assertThat(authenticationToken.getCredentials().getSignature()).isEqualTo(Base64UrlUtil.decode(signature));
		assertThat(authenticationToken.getCredentials().getClientExtensionsJSON()).isEqualTo(clientExtensionsJSON);
		assertThat(authenticationToken.getCredentials().getServerProperty()).isEqualTo(serverProperty);

	}


	@Test
	public void attemptAuthentication_test_with_customized_parameter() {

		String usernameParameter = "param_username";
		String passwordParameter = "param_password";
		String credentialIdParameter = "param_credentialId";
		String clientDataJSONParameter = "param_clientDataJSON";
		String authenticatorDataParameter = "param_authenticatorData";
		String signatureParameter = "param_signature";
		String clientExtensionsJSONParameter = "param_clientExtensionsJSON";

		String credentialId = "AAhdofeLeQWG6Y6gwwytZKNCDFB1WaIgqDsOwVYR5UavKQhAti4ic9_Dz-_CQEPpN0To6hiDRSCvmFHXaG6HK5yvvhm4DJRVJXzSvZiq5NefbXSYIr2uUaKbsoBe1lulhNdL9dRt6Dkkp38uq02YIR5CDaoxD-HQgMsS667aWlhHVKE884Sq0d1VVgGTDb1ds-Py_H7CDqk9SDErb8-XtQ9L";
		String clientDataJSON = "eyJjaGFsbGVuZ2UiOiJGT3JHWklmSFJfeURaSklydTVPdXBBIiwiaGFzaEFsZyI6IlMyNTYiLCJvcmlnaW4iOiJsb2NhbGhvc3QifQ";
		String authenticatorData = "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAABaQ";
		String signature = "MEUCIGBYMUVg2KkMG7V7UEsGxUeKVaO8x587JyVoZkk6FmsgAiEA5XRKxlYe2Vpwn-JYEJhcEVJ3-0nYFG-JfheOk4rA3dc";
		String clientExtensionsJSON = "";

		ServerProperty serverProperty = mock(ServerProperty.class);

		//Given
		target.setUsernameParameter(usernameParameter);
		target.setPasswordParameter(passwordParameter);
		target.setCredentialIdParameter(credentialIdParameter);
		target.setClientDataJSONParameter(clientDataJSONParameter);
		target.setAuthenticatorDataParameter(authenticatorDataParameter);
		target.setSignatureParameter(signatureParameter);
		target.setClientExtensionsJSONParameter(clientExtensionsJSONParameter);
		target.setExpectedAuthenticationExtensionIds(Collections.singletonList(FIDOAppIDExtensionClientInput.ID));

		mockHttpServletRequest.setMethod("POST");
		mockHttpServletRequest.setServerName("example.com");
		mockHttpServletRequest.setParameter(credentialIdParameter, credentialId);
		mockHttpServletRequest.setParameter(clientDataJSONParameter, clientDataJSON);
		mockHttpServletRequest.setParameter(authenticatorDataParameter, authenticatorData);
		mockHttpServletRequest.setParameter(signatureParameter, signature);
		mockHttpServletRequest.setParameter(clientExtensionsJSONParameter, clientExtensionsJSON);

		when(authenticationManager.authenticate(captor.capture())).thenReturn(null);
		when(serverPropertyProvider.provide(any())).thenReturn(serverProperty);

		//When
		target.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);

		//Then
		assertThat(target.getUsernameParameter()).isEqualTo(usernameParameter);
		assertThat(target.getPasswordParameter()).isEqualTo(passwordParameter);
		assertThat(target.getCredentialIdParameter()).isEqualTo(credentialIdParameter);
		assertThat(target.getClientDataJSONParameter()).isEqualTo(clientDataJSONParameter);
		assertThat(target.getAuthenticatorDataParameter()).isEqualTo(authenticatorDataParameter);
		assertThat(target.getSignatureParameter()).isEqualTo(signatureParameter);
		assertThat(target.getClientExtensionsJSONParameter()).isEqualTo(clientExtensionsJSONParameter);
		assertThat(target.getExpectedAuthenticationExtensionIds()).isEqualTo(Collections.singletonList(FIDOAppIDExtensionClientInput.ID));
		assertThat(target.getServerPropertyProvider()).isEqualTo(serverPropertyProvider);


		WebAuthnAssertionAuthenticationToken authenticationToken = (WebAuthnAssertionAuthenticationToken) captor.getValue();
		verify(serverPropertyProvider).provide(mockHttpServletRequest);
		assertThat(authenticationToken.getPrincipal()).isNull();
		assertThat(authenticationToken.getCredentials()).isInstanceOf(WebAuthnAuthenticationRequest.class);
		assertThat(authenticationToken.getCredentials().getCredentialId()).isEqualTo(Base64UrlUtil.decode(credentialId));
		assertThat(authenticationToken.getCredentials().getClientDataJSON()).isEqualTo(Base64UrlUtil.decode(clientDataJSON));
		assertThat(authenticationToken.getCredentials().getAuthenticatorData()).isEqualTo(Base64UrlUtil.decode(authenticatorData));
		assertThat(authenticationToken.getCredentials().getSignature()).isEqualTo(Base64UrlUtil.decode(signature));
		assertThat(authenticationToken.getCredentials().getClientExtensionsJSON()).isEqualTo(clientExtensionsJSON);
		assertThat(authenticationToken.getCredentials().getServerProperty()).isEqualTo(serverProperty);


	}


	@Test(expected = AuthenticationServiceException.class)
	public void attemptAuthentication_test_with_wrong_port() {

		//Given
		mockHttpServletRequest.setMethod("GET");
		when(authenticationManager.authenticate(captor.capture())).thenReturn(null);

		//When
		target.attemptAuthentication(mockHttpServletRequest, mockHttpServletResponse);
	}

	@Test
	public void constructor_test() {
		ServerPropertyProvider serverPropertyProvider = mock(ServerPropertyProvider.class);
		WebAuthnProcessingFilter webAuthnProcessingFilter = new WebAuthnProcessingFilter(AuthorityUtils.NO_AUTHORITIES, serverPropertyProvider);
		assertThat(webAuthnProcessingFilter.getServerPropertyProvider()).isEqualTo(serverPropertyProvider);
	}


}
