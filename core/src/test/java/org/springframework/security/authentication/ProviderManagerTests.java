/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.context.MessageSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests {@link ProviderManager}.
 *
 * @author Ben Alex
 */
public class ProviderManagerTests {

	@Test
	void authenticationFailsWithUnsupportedToken() {
		Authentication token = new AbstractAuthenticationToken(null) {
			@Override
			public Object getCredentials() {
				return "";
			}

			@Override
			public Object getPrincipal() {
				return "";
			}
		};
		ProviderManager mgr = makeProviderManager();
		mgr.setMessageSource(mock(MessageSource.class));
		assertThatExceptionOfType(ProviderNotFoundException.class).isThrownBy(() -> mgr.authenticate(token));
	}

	@Test
	void credentialsAreClearedByDefault() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("Test",
				"Password");
		ProviderManager mgr = makeProviderManager();
		Authentication result = mgr.authenticate(token);
		assertThat(result.getCredentials()).isNull();
		mgr.setEraseCredentialsAfterAuthentication(false);
		token = UsernamePasswordAuthenticationToken.unauthenticated("Test", "Password");
		result = mgr.authenticate(token);
		assertThat(result.getCredentials()).isNotNull();
	}

	@Test
	void authenticationSucceedsWithSupportedTokenAndReturnsExpectedObject() {
		Authentication a = mock(Authentication.class);
		ProviderManager mgr = new ProviderManager(createProviderWhichReturns(a));
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		mgr.setAuthenticationEventPublisher(publisher);
		Authentication result = mgr.authenticate(a);
		assertThat(result).isEqualTo(a);
		verify(publisher).publishAuthenticationSuccess(result);
	}

	@Test
	void authenticationSucceedsWhenFirstProviderReturnsNullButSecondAuthenticates() {
		Authentication a = mock(Authentication.class);
		ProviderManager mgr = new ProviderManager(
				Arrays.asList(createProviderWhichReturns(null), createProviderWhichReturns(a)));
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		mgr.setAuthenticationEventPublisher(publisher);
		Authentication result = mgr.authenticate(a);
		assertThat(result).isSameAs(a);
		verify(publisher).publishAuthenticationSuccess(result);
	}

	@Test
	void testStartupFailsIfProvidersNotSetAsList() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ProviderManager((List<AuthenticationProvider>) null));
	}

	@Test
	void testStartupFailsIfProvidersNotSetAsVarargs() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ProviderManager((AuthenticationProvider) null));
	}

	@Test
	void testStartupFailsIfProvidersContainNullElement() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new ProviderManager(Arrays.asList(mock(AuthenticationProvider.class), null)));
	}

	// gh-8689
	@Test
	void constructorWhenUsingListOfThenNoException() {
		List<AuthenticationProvider> providers = spy(ArrayList.class);
		// List.of(null) in JDK 9 throws a NullPointerException
		given(providers.contains(eq(null))).willThrow(NullPointerException.class);
		providers.add(mock(AuthenticationProvider.class));
		new ProviderManager(providers);
	}

	@Test
	void detailsAreNotSetOnAuthenticationTokenIfAlreadySetByProvider() {
		Object requestDetails = "(Request Details)";
		final Object resultDetails = "(Result Details)";
		// A provider which sets the details object
		AuthenticationProvider provider = new AuthenticationProvider() {
			@Override
			public Authentication authenticate(Authentication authentication) throws AuthenticationException {
				((TestingAuthenticationToken) authentication).setDetails(resultDetails);
				return authentication;
			}

			@Override
			public boolean supports(Class<?> authentication) {
				return true;
			}
		};
		ProviderManager authMgr = new ProviderManager(provider);
		TestingAuthenticationToken request = createAuthenticationToken();
		request.setDetails(requestDetails);
		Authentication result = authMgr.authenticate(request);
		assertThat(result.getDetails()).isEqualTo(resultDetails);
	}

	@Test
	void detailsAreSetOnAuthenticationTokenIfNotAlreadySetByProvider() {
		Object details = new Object();
		ProviderManager authMgr = makeProviderManager();
		TestingAuthenticationToken request = createAuthenticationToken();
		request.setDetails(details);
		Authentication result = authMgr.authenticate(request);
		assertThat(result.getCredentials()).isNotNull();
		assertThat(result.getDetails()).isSameAs(details);
	}

	@Test
	void authenticationExceptionIsIgnoredIfLaterProviderAuthenticates() {
		Authentication authReq = mock(Authentication.class);
		ProviderManager mgr = new ProviderManager(
				createProviderWhichThrows(new BadCredentialsException("", new Throwable())),
				createProviderWhichReturns(authReq));
		assertThat(mgr.authenticate(mock(Authentication.class))).isSameAs(authReq);
	}

	@Test
	void authenticationExceptionIsRethrownIfNoLaterProviderAuthenticates() {
		ProviderManager mgr = new ProviderManager(Arrays
			.asList(createProviderWhichThrows(new BadCredentialsException("")), createProviderWhichReturns(null)));
		assertThatExceptionOfType(BadCredentialsException.class)
			.isThrownBy(() -> mgr.authenticate(mock(Authentication.class)));
	}

	// SEC-546
	@Test
	void accountStatusExceptionPreventsCallsToSubsequentProviders() {
		AuthenticationProvider iThrowAccountStatusException = createProviderWhichThrows(new AccountStatusException("") {
		});
		AuthenticationProvider otherProvider = mock(AuthenticationProvider.class);
		ProviderManager authMgr = new ProviderManager(Arrays.asList(iThrowAccountStatusException, otherProvider));
		assertThatExceptionOfType(AccountStatusException.class)
			.isThrownBy(() -> authMgr.authenticate(mock(Authentication.class)));
		verifyNoInteractions(otherProvider);
	}

	@Test
	void parentAuthenticationIsUsedIfProvidersDontAuthenticate() {
		AuthenticationManager parent = mock(AuthenticationManager.class);
		Authentication authReq = mock(Authentication.class);
		given(parent.authenticate(authReq)).willReturn(authReq);
		ProviderManager mgr = new ProviderManager(List.of(mock(AuthenticationProvider.class)), parent);
		assertThat(mgr.authenticate(authReq)).isSameAs(authReq);
	}

	@Test
	void parentIsNotCalledIfAccountStatusExceptionIsThrown() {
		AuthenticationProvider iThrowAccountStatusException = createProviderWhichThrows(
				new AccountStatusException("", new Throwable()) {
				});
		AuthenticationManager parent = mock(AuthenticationManager.class);
		ProviderManager mgr = new ProviderManager(List.of(iThrowAccountStatusException), parent);
		assertThatExceptionOfType(AccountStatusException.class)
			.isThrownBy(() -> mgr.authenticate(mock(Authentication.class)));
		verifyNoInteractions(parent);
	}

	@Test
	void providerNotFoundFromParentIsIgnored() {
		final Authentication authReq = mock(Authentication.class);
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		AuthenticationManager parent = mock(AuthenticationManager.class);
		given(parent.authenticate(authReq)).willThrow(new ProviderNotFoundException(""));
		// Set a provider that throws an exception - this is the exception we expect to be
		// propagated
		ProviderManager mgr = new ProviderManager(List.of(createProviderWhichThrows(new BadCredentialsException(""))),
				parent);
		mgr.setAuthenticationEventPublisher(publisher);
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> mgr.authenticate(authReq))
			.satisfies((ex) -> verify(publisher).publishAuthenticationFailure(ex, authReq));
	}

	@Test
	void authenticationExceptionFromParentOverridesPreviousOnes() {
		AuthenticationManager parent = mock(AuthenticationManager.class);
		ProviderManager mgr = new ProviderManager(List.of(createProviderWhichThrows(new BadCredentialsException(""))),
				parent);
		Authentication authReq = mock(Authentication.class);
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		mgr.setAuthenticationEventPublisher(publisher);
		// Set a provider that throws an exception - this is the exception we expect to be
		// propagated
		BadCredentialsException expected = new BadCredentialsException("I'm the one from the parent");
		given(parent.authenticate(authReq)).willThrow(expected);
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> mgr.authenticate(authReq))
			.isSameAs(expected);
	}

	@Test
	void statusExceptionIsPublished() {
		AuthenticationManager parent = mock(AuthenticationManager.class);
		LockedException expected = new LockedException("");
		ProviderManager mgr = new ProviderManager(List.of(createProviderWhichThrows(expected)), parent);
		Authentication authReq = mock(Authentication.class);
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		mgr.setAuthenticationEventPublisher(publisher);
		assertThatExceptionOfType(LockedException.class).isThrownBy(() -> mgr.authenticate(authReq));
		verify(publisher).publishAuthenticationFailure(expected, authReq);
	}

	@Test
	void whenAccountStatusExceptionThenAuthenticationRequestIsIncluded() {
		AuthenticationException expected = new LockedException("");
		ProviderManager mgr = new ProviderManager(createProviderWhichThrows(expected));
		Authentication authReq = mock(Authentication.class);
		assertThatExceptionOfType(LockedException.class).isThrownBy(() -> mgr.authenticate(authReq));
		assertThat(expected.getAuthenticationRequest()).isEqualTo(authReq);
	}

	@Test
	void whenInternalServiceAuthenticationExceptionThenAuthenticationRequestIsIncluded() {
		AuthenticationException expected = new InternalAuthenticationServiceException("");
		ProviderManager mgr = new ProviderManager(createProviderWhichThrows(expected));
		Authentication authReq = mock(Authentication.class);
		assertThatExceptionOfType(InternalAuthenticationServiceException.class)
			.isThrownBy(() -> mgr.authenticate(authReq));
		assertThat(expected.getAuthenticationRequest()).isEqualTo(authReq);
	}

	@Test
	void whenAuthenticationExceptionThenAuthenticationRequestIsIncluded() {
		AuthenticationException expected = new BadCredentialsException("");
		ProviderManager mgr = new ProviderManager(createProviderWhichThrows(expected));
		Authentication authReq = mock(Authentication.class);
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> mgr.authenticate(authReq));
		assertThat(expected.getAuthenticationRequest()).isEqualTo(authReq);
	}

	// SEC-2367
	@Test
	void providerThrowsInternalAuthenticationServiceException() {
		InternalAuthenticationServiceException expected = new InternalAuthenticationServiceException("Expected");
		ProviderManager mgr = new ProviderManager(Arrays.asList(createProviderWhichThrows(expected),
				createProviderWhichThrows(new BadCredentialsException("Oops"))), null);
		Authentication authReq = mock(Authentication.class);
		assertThatExceptionOfType(InternalAuthenticationServiceException.class)
			.isThrownBy(() -> mgr.authenticate(authReq));
	}

	// gh-6281
	@Test
	void authenticateWhenFailsInParentAndPublishesThenChildDoesNotPublish() {
		BadCredentialsException badCredentialsExParent = new BadCredentialsException("Bad Credentials in parent");
		ProviderManager parentMgr = new ProviderManager(createProviderWhichThrows(badCredentialsExParent));
		ProviderManager childMgr = new ProviderManager(
				List.of(createProviderWhichThrows(new BadCredentialsException("Bad Credentials in child"))), parentMgr);
		AuthenticationEventPublisher publisher = mock(AuthenticationEventPublisher.class);
		parentMgr.setAuthenticationEventPublisher(publisher);
		childMgr.setAuthenticationEventPublisher(publisher);
		Authentication authReq = mock(Authentication.class);
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> childMgr.authenticate(authReq))
			.isSameAs(badCredentialsExParent);
		verify(publisher).publishAuthenticationFailure(badCredentialsExParent, authReq); // Parent
																							// publishes
		verifyNoMoreInteractions(publisher); // Child should not publish (duplicate event)
	}

	private AuthenticationProvider createProviderWhichThrows(final AuthenticationException ex) {
		AuthenticationProvider provider = mock(AuthenticationProvider.class);
		given(provider.supports(any(Class.class))).willReturn(true);
		given(provider.authenticate(any(Authentication.class))).willThrow(ex);
		return provider;
	}

	private AuthenticationProvider createProviderWhichReturns(final Authentication a) {
		AuthenticationProvider provider = mock(AuthenticationProvider.class);
		given(provider.supports(any(Class.class))).willReturn(true);
		given(provider.authenticate(any(Authentication.class))).willReturn(a);
		return provider;
	}

	private TestingAuthenticationToken createAuthenticationToken() {
		return new TestingAuthenticationToken("name", "password", new ArrayList<>(0));
	}

	private ProviderManager makeProviderManager() {
		MockProvider provider = new MockProvider();
		return new ProviderManager(provider);
	}

	private static class MockProvider implements AuthenticationProvider {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			if (supports(authentication.getClass())) {
				return authentication;
			}
			else {
				throw new AuthenticationServiceException("Don't support this class");
			}
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return TestingAuthenticationToken.class.isAssignableFrom(authentication)
					|| UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
		}

	}

}
