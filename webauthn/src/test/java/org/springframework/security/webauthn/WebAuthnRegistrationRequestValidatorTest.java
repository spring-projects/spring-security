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

import com.webauthn4j.data.WebAuthnRegistrationContext;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidationResponse;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.webauthn.exception.BadAttestationStatementException;
import org.springframework.security.webauthn.server.ServerPropertyProvider;

import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Test for WebAuthnRegistrationContextValidator
 */
public class WebAuthnRegistrationRequestValidatorTest {

	@Rule
	public MockitoRule mockito = MockitoJUnit.rule();

	@Mock
	private WebAuthnRegistrationContextValidator registrationContextValidator;

	@Mock
	private ServerPropertyProvider serverPropertyProvider;


	@Test
	public void validate_test() {
		WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(
				registrationContextValidator, serverPropertyProvider
		);

		ServerProperty serverProperty = mock(ServerProperty.class);
		when(serverPropertyProvider.provide(any())).thenReturn(serverProperty);

		CollectedClientData collectedClientData = mock(CollectedClientData.class);
		AttestationObject attestationObject = mock(AttestationObject.class);
		AuthenticationExtensionsClientOutputs clientExtensionOutputs = new AuthenticationExtensionsClientOutputs();
		when(registrationContextValidator.validate(any())).thenReturn(
				new WebAuthnRegistrationContextValidationResponse(collectedClientData, attestationObject, clientExtensionOutputs));

		MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
		mockHttpServletRequest.setScheme("https");
		mockHttpServletRequest.setServerName("example.com");
		mockHttpServletRequest.setServerPort(443);
		String clientDataBase64 = "clientDataBase64";
		String attestationObjectBase64 = "attestationObjectBase64";
		Set<String> transports = Collections.emptySet();
		String clientExtensionsJSON = "clientExtensionsJSON";

		target.validate(mockHttpServletRequest, clientDataBase64, attestationObjectBase64, transports, clientExtensionsJSON);

		ArgumentCaptor<WebAuthnRegistrationContext> argumentCaptor = ArgumentCaptor.forClass(WebAuthnRegistrationContext.class);
		verify(registrationContextValidator).validate(argumentCaptor.capture());
		WebAuthnRegistrationContext registrationContext = argumentCaptor.getValue();

		assertThat(registrationContext.getClientDataJSON()).isEqualTo(Base64UrlUtil.decode(clientDataBase64));
		assertThat(registrationContext.getAttestationObject()).isEqualTo(Base64UrlUtil.decode(attestationObjectBase64));
		assertThat(registrationContext.getClientExtensionsJSON()).isEqualTo(clientExtensionsJSON);
		assertThat(registrationContext.getServerProperty()).isEqualTo(serverProperty);
		assertThat(registrationContext.getExpectedExtensionIds()).isEqualTo(target.getExpectedRegistrationExtensionIds());
	}

	@Test
	public void validate_with_transports_null_test() {
		WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(
				registrationContextValidator, serverPropertyProvider
		);

		ServerProperty serverProperty = mock(ServerProperty.class);
		when(serverPropertyProvider.provide(any())).thenReturn(serverProperty);

		CollectedClientData collectedClientData = mock(CollectedClientData.class);
		AttestationObject attestationObject = mock(AttestationObject.class);
		AuthenticationExtensionsClientOutputs clientExtensionOutputs = new AuthenticationExtensionsClientOutputs();
		when(registrationContextValidator.validate(any())).thenReturn(
				new WebAuthnRegistrationContextValidationResponse(collectedClientData, attestationObject, clientExtensionOutputs));

		MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
		mockHttpServletRequest.setScheme("https");
		mockHttpServletRequest.setServerName("example.com");
		mockHttpServletRequest.setServerPort(443);
		String clientDataBase64 = "clientDataBase64";
		String attestationObjectBase64 = "attestationObjectBase64";
		String clientExtensionsJSON = "clientExtensionsJSON";

		target.validate(mockHttpServletRequest, clientDataBase64, attestationObjectBase64, null, clientExtensionsJSON);

		ArgumentCaptor<WebAuthnRegistrationContext> argumentCaptor = ArgumentCaptor.forClass(WebAuthnRegistrationContext.class);
		verify(registrationContextValidator).validate(argumentCaptor.capture());
		WebAuthnRegistrationContext registrationContext = argumentCaptor.getValue();

		assertThat(registrationContext.getClientDataJSON()).isEqualTo(Base64UrlUtil.decode(clientDataBase64));
		assertThat(registrationContext.getAttestationObject()).isEqualTo(Base64UrlUtil.decode(attestationObjectBase64));
		assertThat(registrationContext.getClientExtensionsJSON()).isEqualTo(clientExtensionsJSON);
		assertThat(registrationContext.getServerProperty()).isEqualTo(serverProperty);
		assertThat(registrationContext.getExpectedExtensionIds()).isEqualTo(target.getExpectedRegistrationExtensionIds());
	}


	@Test
	public void getter_setter_test() {
		WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(
				registrationContextValidator, serverPropertyProvider
		);
		target.setExpectedRegistrationExtensionIds(Collections.singletonList("appId"));
		assertThat(target.getExpectedRegistrationExtensionIds()).containsExactly("appId");

	}

	@Test(expected = BadAttestationStatementException.class)
	public void validate_caught_exception_test() {
		WebAuthnRegistrationRequestValidator target = new WebAuthnRegistrationRequestValidator(
				registrationContextValidator, serverPropertyProvider
		);
		when(registrationContextValidator.validate(any())).thenThrow(new com.webauthn4j.validator.exception.BadAttestationStatementException("dummy"));

		MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
		mockHttpServletRequest.setScheme("https");
		mockHttpServletRequest.setServerName("example.com");
		mockHttpServletRequest.setServerPort(443);
		String clientDataBase64 = "clientDataBase64";
		String attestationObjectBase64 = "attestationObjectBase64";
		Set<String> transports = Collections.emptySet();
		String clientExtensionsJSON = "clientExtensionsJSON";

		target.validate(mockHttpServletRequest, clientDataBase64, attestationObjectBase64, transports, clientExtensionsJSON);

	}
}
