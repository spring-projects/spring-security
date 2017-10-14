/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.registration;

import org.junit.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationValidator;
import org.springframework.security.oauth2.client.registration.DefaultClientRegistrationValidator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * A Test for Validator for OAuth 2.0 / OpenID Connect 1.0 {@link DefaultClientRegistrationValidator}'s.
 *
 *
 * @author Shazin Sadakath
 * @since 5.0
 * @see DefaultClientRegistrationValidator
 */
public class DefaultClientRegistrationValidatorTests {

	private final ClientRegistrationValidator clientRegistrationValidator = new DefaultClientRegistrationValidator();

	@Test
	public void validateWhenClientRegistrationIsValid() {
		ClientRegistration clientRegistration = new ClientRegistration.Builder("some-register-id")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.clientId("some-client-id")
			.clientSecret("some-client-secret")
			.clientName("some-client-name")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.scope("READ")
			.authorizationUri("http://www.google.com")
			.tokenUri("http://www.facebook.com")
			.redirectUri("http://www.stackoverflow.com")
			.build();
		clientRegistrationValidator.validate(clientRegistration);
	}

	@Test(expected = IllegalArgumentException.class)
	public void validateWhenAuthorizationUriIsInvalid() {
		ClientRegistration clientRegistration = new ClientRegistration.Builder("some-register-id")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.clientId("some-client-id")
			.clientSecret("some-client-secret")
			.clientName("some-client-name")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.scope("READ")
			.authorizationUri("invalid-uri")
			.tokenUri("http://www.facebook.com")
			.redirectUri("http://www.stackoverflow.com")
			.build();
		clientRegistrationValidator.validate(clientRegistration);
	}

	@Test(expected = IllegalArgumentException.class)
	public void validateWhenTokenUriIsInvalid() {
		ClientRegistration clientRegistration = new ClientRegistration.Builder("some-register-id")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.clientId("some-client-id")
			.clientSecret("some-client-secret")
			.clientName("some-client-name")
			.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
			.scope("READ")
			.authorizationUri("http://www.google.com")
			.tokenUri("invalid-uri")
			.redirectUri("http://www.stackoverflow.com")
			.build();
		clientRegistrationValidator.validate(clientRegistration);
	}


}
