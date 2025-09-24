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

package org.springframework.security.web.webauthn.authentication;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.SecurityAssertions;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthorities;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.TestAuthenticationAssertionResponses;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialUserEntities;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentials;
import org.springframework.security.web.webauthn.management.RelyingPartyAuthenticationRequest;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

class WebAuthnAuthenticationProviderTests {

	@Test
	void authenticateWhenSuccessThenIssuesFactor() {
		WebAuthnRelyingPartyOperations operations = mock(WebAuthnRelyingPartyOperations.class);
		UserDetailsService users = mock(UserDetailsService.class);
		PublicKeyCredentialRequestOptions options = TestPublicKeyCredentialRequestOptions.create().build();
		AuthenticatorAssertionResponse response = TestAuthenticationAssertionResponses
			.createAuthenticatorAssertionResponse()
			.build();
		PublicKeyCredential<AuthenticatorAssertionResponse> credentials = TestPublicKeyCredentials
			.createPublicKeyCredential(response)
			.build();
		Authentication request = new WebAuthnAuthenticationRequestToken(
				new RelyingPartyAuthenticationRequest(options, credentials));
		WebAuthnAuthenticationProvider provider = new WebAuthnAuthenticationProvider(operations, users);
		given(users.loadUserByUsername(any())).willReturn(PasswordEncodedUser.user());
		given(operations.authenticate(any())).willReturn(TestPublicKeyCredentialUserEntities.userEntity().build());
		Authentication result = provider.authenticate(request);
		SecurityAssertions.assertThat(result).hasAuthority(GrantedAuthorities.FACTOR_WEBAUTHN_AUTHORITY);
	}

}
