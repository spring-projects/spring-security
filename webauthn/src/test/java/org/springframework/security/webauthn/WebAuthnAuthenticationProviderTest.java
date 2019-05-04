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

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.data.WebAuthnAuthenticationContext;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import org.springframework.security.webauthn.exception.BadChallengeException;
import org.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import org.springframework.security.webauthn.request.WebAuthnAuthenticationRequest;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsImpl;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Test for WebAuthnAuthenticationProvider
 */
public class WebAuthnAuthenticationProviderTest {

	private WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);

	private WebAuthnAuthenticatorService authenticatorService = mock(WebAuthnAuthenticatorService.class);

	private WebAuthnAuthenticationContextValidator authenticationContextValidator = mock(WebAuthnAuthenticationContextValidator.class);

	private WebAuthnAuthenticationProvider authenticationProvider
			= new WebAuthnAuthenticationProvider(userDetailsService, authenticatorService, authenticationContextValidator);

	@Before
	public void setup() {
		authenticationProvider = new WebAuthnAuthenticationProvider(userDetailsService, authenticatorService, authenticationContextValidator);
	}

	/**
	 * Verifies that an unsupported authentication token will be rejected.
	 */
	@Test(expected = IllegalArgumentException.class)
	public void authenticate_with_invalid_authenticationToken() {
		Authentication token = new UsernamePasswordAuthenticationToken("username", "password");
		authenticationProvider.authenticate(token);
	}

	/**
	 * Verifies that the authentication token without credentials will be rejected.
	 */
	@Test(expected = BadCredentialsException.class)
	public void authenticate_with_authenticationToken_without_credentials() {
		Authentication token = new WebAuthnAssertionAuthenticationToken(null);
		authenticationProvider.authenticate(token);
	}


	/**
	 * Verifies that authentication process passes successfully if input is correct.
	 */
	@Test
	public void authenticate_test() {
		//Given
		byte[] credentialId = new byte[32];
		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
		WebAuthnAuthenticator authenticator = mock(WebAuthnAuthenticator.class, RETURNS_DEEP_STUBS);
		WebAuthnUserDetailsImpl user = new WebAuthnUserDetailsImpl(
				new byte[0],
				"dummy",
				"dummy",
				Collections.singletonList(authenticator),
				Collections.singletonList(grantedAuthority));
		when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);

		//When
		WebAuthnAuthenticationRequest credential = mock(WebAuthnAuthenticationRequest.class);
		when(credential.getCredentialId()).thenReturn(credentialId);
		when(userDetailsService.loadUserByCredentialId(credentialId)).thenReturn(user);
		Authentication token = new WebAuthnAssertionAuthenticationToken(credential);
		Authentication authenticatedToken = authenticationProvider.authenticate(token);

		ArgumentCaptor<WebAuthnAuthenticationContext> captor = ArgumentCaptor.forClass(WebAuthnAuthenticationContext.class);
		verify(authenticationContextValidator).validate(captor.capture(), any());
		WebAuthnAuthenticationContext authenticationContext = captor.getValue();

		assertThat(authenticationContext.getExpectedExtensionIds()).isEqualTo(credential.getExpectedAuthenticationExtensionIds());

		assertThat(authenticatedToken.getPrincipal()).isInstanceOf(WebAuthnUserDetailsImpl.class);
		assertThat(authenticatedToken.getCredentials()).isEqualTo(credential);
		assertThat(authenticatedToken.getAuthorities().toArray()).containsExactly(grantedAuthority);
	}

	/**
	 * Verifies that authentication process passes successfully if input is correct.
	 */
	@Test
	public void authenticate_with_forcePrincipalAsString_option_test() {
		//Given
		byte[] credentialId = new byte[32];
		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
		WebAuthnAuthenticator authenticator = mock(WebAuthnAuthenticator.class, RETURNS_DEEP_STUBS);
		WebAuthnUserDetailsImpl user = new WebAuthnUserDetailsImpl(
				new byte[0],
				"dummy",
				"dummy",
				Collections.singletonList(authenticator),
				Collections.singletonList(grantedAuthority));
		when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);

		//When
		WebAuthnAuthenticationRequest credential = mock(WebAuthnAuthenticationRequest.class);
		when(credential.getCredentialId()).thenReturn(credentialId);
		when(userDetailsService.loadUserByCredentialId(credentialId)).thenReturn(user);
		Authentication token = new WebAuthnAssertionAuthenticationToken(credential);
		authenticationProvider.setForcePrincipalAsString(true);
		Authentication authenticatedToken = authenticationProvider.authenticate(token);

		assertThat(authenticatedToken.getPrincipal()).isInstanceOf(String.class);
		assertThat(authenticatedToken.getCredentials()).isEqualTo(credential);
		assertThat(authenticatedToken.getAuthorities().toArray()).containsExactly(grantedAuthority);
	}

	/**
	 * Verifies that validation fails if ValidationException is thrown from authenticationContextValidator
	 */
	@Test(expected = BadChallengeException.class)
	public void authenticate_with_BadChallengeException_from_authenticationContextValidator_test() {
		//Given
		byte[] credentialId = new byte[32];
		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
		WebAuthnAuthenticator authenticator = mock(WebAuthnAuthenticator.class, RETURNS_DEEP_STUBS);
		WebAuthnUserDetailsImpl user = new WebAuthnUserDetailsImpl(
				new byte[0],
				"dummy",
				"dummy",
				Collections.singletonList(authenticator),
				Collections.singletonList(grantedAuthority));
		when(authenticator.getAttestedCredentialData().getCredentialId()).thenReturn(credentialId);

		doThrow(com.webauthn4j.validator.exception.BadChallengeException.class).when(authenticationContextValidator).validate(any(), any());

		//When
		WebAuthnAuthenticationRequest credential = mock(WebAuthnAuthenticationRequest.class);
		when(credential.getCredentialId()).thenReturn(credentialId);
		when(userDetailsService.loadUserByCredentialId(credentialId)).thenReturn(user);
		Authentication token = new WebAuthnAssertionAuthenticationToken(credential);
		authenticationProvider.authenticate(token);
	}


	@Test
	public void retrieveWebAuthnUserDetails_test() {
		byte[] credentialId = new byte[0];
		WebAuthnUserDetails expectedUser = mock(WebAuthnUserDetails.class);

		//Given
		when(userDetailsService.loadUserByCredentialId(credentialId)).thenReturn(expectedUser);

		//When
		WebAuthnUserDetails userDetails = authenticationProvider.retrieveWebAuthnUserDetails(credentialId);

		//Then
		assertThat(userDetails).isEqualTo(expectedUser);

	}

	@Test(expected = BadCredentialsException.class)
	public void retrieveWebAuthnUserDetails_test_with_CredentialIdNotFoundException() {
		byte[] credentialId = new byte[0];

		//Given
		when(userDetailsService.loadUserByCredentialId(credentialId)).thenThrow(CredentialIdNotFoundException.class);

		//When
		authenticationProvider.retrieveWebAuthnUserDetails(credentialId);
	}

	@Test(expected = CredentialIdNotFoundException.class)
	public void retrieveWebAuthnUserDetails_test_with_CredentialIdNotFoundException_and_hideCredentialIdNotFoundExceptions_option_false() {
		byte[] credentialId = new byte[0];

		//Given
		when(userDetailsService.loadUserByCredentialId(credentialId)).thenThrow(CredentialIdNotFoundException.class);

		//When
		authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
		authenticationProvider.retrieveWebAuthnUserDetails(credentialId);
	}

	@Test(expected = InternalAuthenticationServiceException.class)
	public void retrieveWebAuthnUserDetails_test_with_RuntimeException_from_webAuthnAuthenticatorService() {
		byte[] credentialId = new byte[0];

		//Given
		when(userDetailsService.loadUserByCredentialId(credentialId)).thenThrow(RuntimeException.class);

		//When
		authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
		authenticationProvider.retrieveWebAuthnUserDetails(credentialId);
	}

	@Test(expected = InternalAuthenticationServiceException.class)
	public void retrieveWebAuthnUserDetails_test_with_null_from_webAuthnAuthenticatorService() {
		byte[] credentialId = new byte[0];

		//Given
		when(userDetailsService.loadUserByCredentialId(credentialId)).thenReturn(null);

		//When
		authenticationProvider.setHideCredentialIdNotFoundExceptions(false);
		authenticationProvider.retrieveWebAuthnUserDetails(credentialId);
	}

	@Test
	public void getter_setter_test() {
		WebAuthnUserDetailsService userDetailsService = mock(WebAuthnUserDetailsService.class);
		UserDetailsChecker preAuthenticationChecker = mock(UserDetailsChecker.class);
		UserDetailsChecker postAuthenticationChecker = mock(UserDetailsChecker.class);

		authenticationProvider.setForcePrincipalAsString(true);
		assertThat(authenticationProvider.isForcePrincipalAsString()).isTrue();
		authenticationProvider.setHideCredentialIdNotFoundExceptions(true);
		assertThat(authenticationProvider.isHideCredentialIdNotFoundExceptions()).isTrue();

		authenticationProvider.setUserDetailsService(userDetailsService);
		assertThat(authenticationProvider.getUserDetailsService()).isEqualTo(userDetailsService);

		authenticationProvider.setPreAuthenticationChecks(preAuthenticationChecker);
		assertThat(authenticationProvider.getPreAuthenticationChecks()).isEqualTo(preAuthenticationChecker);
		authenticationProvider.setPostAuthenticationChecks(postAuthenticationChecker);
		assertThat(authenticationProvider.getPostAuthenticationChecks()).isEqualTo(postAuthenticationChecker);

	}

	@Test
	public void userDetailsChecker_check_test() {
		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
		Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
		WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
				new byte[0],
				"dummy",
				"dummy",
				Collections.singletonList(authenticator),
				Collections.singletonList(grantedAuthority));
		authenticationProvider.getPreAuthenticationChecks().check(userDetails);
	}

	@Test(expected = DisabledException.class)
	public void userDetailsChecker_check_with_disabled_userDetails_test() {
		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
		Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
		WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
				new byte[0],
				"dummy",
				"dummy",
				Collections.singletonList(authenticator),
				true,
				false,
				true,
				true,
				true,
				Collections.singletonList(grantedAuthority));
		authenticationProvider.getPreAuthenticationChecks().check(userDetails);
	}

	@Test(expected = AccountExpiredException.class)
	public void userDetailsChecker_check_with_expired_userDetails_test() {
		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
		Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
		WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
				new byte[0],
				"dummy",
				"dummy",
				Collections.singletonList(authenticator),
				true,
				true,
				false,
				true,
				true,
				Collections.singletonList(grantedAuthority));
		authenticationProvider.getPreAuthenticationChecks().check(userDetails);
	}

	@Test(expected = CredentialsExpiredException.class)
	public void userDetailsChecker_check_with_credentials_expired_userDetails_test() {
		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
		Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
		WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
				new byte[0],
				"dummy",
				"dummy",
				Collections.singletonList(authenticator),
				true,
				true,
				true,
				false,
				true,
				Collections.singletonList(grantedAuthority));
		authenticationProvider.getPostAuthenticationChecks().check(userDetails);
	}

	@Test(expected = LockedException.class)
	public void userDetailsChecker_check_with_locked_userDetails_test() {
		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
		Authenticator authenticator = new AuthenticatorImpl(null, null, 0);
		WebAuthnUserDetailsImpl userDetails = new WebAuthnUserDetailsImpl(
				new byte[0],
				"dummy",
				"dummy",
				Collections.singletonList(authenticator),
				true,
				true,
				true,
				true,
				false,
				Collections.singletonList(grantedAuthority));
		authenticationProvider.getPreAuthenticationChecks().check(userDetails);
	}

	@Test
	public void isUserVerificationRequired_test() {
		WebAuthnUserDetails webAuthnUserDetails = mock(WebAuthnUserDetails.class);
		when(webAuthnUserDetails.getUsername()).thenReturn("john.doe");
		WebAuthnAuthenticationRequest credentials = mock(WebAuthnAuthenticationRequest.class);
		when(credentials.isUserVerificationRequired()).thenReturn(true);
		SecurityContext securityContext = mock(SecurityContext.class);
		Authentication authentication = mock(Authentication.class);
		when(authentication.isAuthenticated()).thenReturn(true);
		when(authentication.getName()).thenReturn("john.doe");
		when(securityContext.getAuthentication()).thenReturn(authentication);
		SecurityContextHolder.setContext(securityContext);
		assertThat(authenticationProvider.isUserVerificationRequired(webAuthnUserDetails, credentials)).isFalse();
	}

}
