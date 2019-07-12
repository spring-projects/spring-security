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

import com.webauthn4j.util.Base64UrlUtil;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.webauthn.server.WebAuthnServerProperty;
import org.springframework.security.webauthn.server.WebAuthnServerPropertyProvider;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Test for {@link WebAuthnRegistrationRequestValidator}
 */
public class WebAuthnRegistrationRequestValidatorTest {

	@Rule
	public MockitoRule mockito = MockitoJUnit.rule();

	@Mock
	private WebAuthnManager webAuthnManager;

	@Mock
	private WebAuthnServerPropertyProvider webAuthnServerPropertyProvider;

	private WebAuthnRegistrationRequestValidator target;

	@Before
	public void setup() {
		target = new WebAuthnRegistrationRequestValidator(webAuthnManager, webAuthnServerPropertyProvider);
	}

	@Test
	public void validate_test() {

		WebAuthnServerProperty serverProperty = mock(WebAuthnServerProperty.class);
		when(webAuthnServerPropertyProvider.provide(any())).thenReturn(serverProperty);

		doNothing().when(webAuthnManager).verifyRegistrationData(any());

		MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
		mockHttpServletRequest.setScheme("https");
		mockHttpServletRequest.setServerName("example.com");
		mockHttpServletRequest.setServerPort(443);
		String clientDataBase64 = "clientDataBase64";
		String attestationObjectBase64 = "attestationObjectBase64";
		Set<String> transports = Collections.emptySet();
		String clientExtensionsJSON = "clientExtensionsJSON";

		target.validate(new WebAuthnRegistrationRequest(mockHttpServletRequest, clientDataBase64, attestationObjectBase64, transports, clientExtensionsJSON));

		ArgumentCaptor<WebAuthnRegistrationData> argumentCaptor = ArgumentCaptor.forClass(WebAuthnRegistrationData.class);
		verify(webAuthnManager).verifyRegistrationData(argumentCaptor.capture());
		WebAuthnRegistrationData registrationData = argumentCaptor.getValue();

		assertThat(registrationData.getClientDataJSON()).isEqualTo(Base64UrlUtil.decode(clientDataBase64));
		assertThat(registrationData.getAttestationObject()).isEqualTo(Base64UrlUtil.decode(attestationObjectBase64));
		assertThat(registrationData.getClientExtensionsJSON()).isEqualTo(clientExtensionsJSON);
		assertThat(registrationData.getServerProperty()).isEqualTo(serverProperty);
		assertThat(registrationData.getExpectedRegistrationExtensionIds()).isEqualTo(target.getExpectedRegistrationExtensionIds());
	}

	@Test
	public void validate_with_transports_null_test() {

		WebAuthnServerProperty serverProperty = mock(WebAuthnServerProperty.class);
		when(webAuthnServerPropertyProvider.provide(any())).thenReturn(serverProperty);

		doNothing().when(webAuthnManager).verifyRegistrationData(any());

		MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
		mockHttpServletRequest.setScheme("https");
		mockHttpServletRequest.setServerName("example.com");
		mockHttpServletRequest.setServerPort(443);
		String clientDataBase64 = "clientDataBase64";
		String attestationObjectBase64 = "attestationObjectBase64";
		String clientExtensionsJSON = "clientExtensionsJSON";

		target.validate(new WebAuthnRegistrationRequest(mockHttpServletRequest, clientDataBase64, attestationObjectBase64, null, clientExtensionsJSON));

		ArgumentCaptor<WebAuthnRegistrationData> argumentCaptor = ArgumentCaptor.forClass(WebAuthnRegistrationData.class);
		verify(webAuthnManager).verifyRegistrationData(argumentCaptor.capture());
		WebAuthnRegistrationData registrationData = argumentCaptor.getValue();

		assertThat(registrationData.getClientDataJSON()).isEqualTo(Base64UrlUtil.decode(clientDataBase64));
		assertThat(registrationData.getAttestationObject()).isEqualTo(Base64UrlUtil.decode(attestationObjectBase64));
		assertThat(registrationData.getClientExtensionsJSON()).isEqualTo(clientExtensionsJSON);
		assertThat(registrationData.getServerProperty()).isEqualTo(serverProperty);
		assertThat(registrationData.getExpectedRegistrationExtensionIds()).isEqualTo(target.getExpectedRegistrationExtensionIds());
	}


	@Test
	public void getter_setter_test() {

		target.setExpectedRegistrationExtensionIds(Collections.singletonList("appId"));
		assertThat(target.getExpectedRegistrationExtensionIds()).containsExactly("appId");

	}
}
