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

package org.springframework.security.authentication.dao;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.cache.Cache;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.authentication.password.CompromisedPasswordException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.core.userdetails.cache.SpringCacheBasedUserCache;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests {@link DaoAuthenticationProvider}.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class DaoAuthenticationProviderTests {

	private static final List<GrantedAuthority> ROLES_12 = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");

	@Test
	public void testAuthenticateFailsForIncorrectPasswordCase() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("rod", "KOala");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testReceivedBadCredentialsWhenCredentialsNotProvided() {
		// Test related to SEC-434
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.setUserCache(new MockUserCache());
		UsernamePasswordAuthenticationToken authenticationToken = UsernamePasswordAuthenticationToken
			.unauthenticated("rod", null);
		assertThatExceptionOfType(BadCredentialsException.class)
			.isThrownBy(() -> provider.authenticate(authenticationToken));
	}

	@Test
	public void testAuthenticateFailsIfAccountExpired() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("peter",
				"opal");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserPeterAccountExpired());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(AccountExpiredException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testAuthenticateFailsIfAccountLocked() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("peter",
				"opal");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserPeterAccountLocked());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(LockedException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testAuthenticateFailsIfCredentialsExpired() {
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserPeterCredentialsExpired());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(CredentialsExpiredException.class).isThrownBy(
				() -> provider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("peter", "opal")));
		// Check that wrong password causes BadCredentialsException, rather than
		// CredentialsExpiredException
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider
			.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("peter", "wrong_password")));
	}

	@Test
	public void testAuthenticateFailsIfUserDisabled() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("peter",
				"opal");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserPeter());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(DisabledException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testAuthenticateFailsWhenAuthenticationDaoHasBackendFailure() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("rod", "koala");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceSimulateBackendError());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(InternalAuthenticationServiceException.class)
			.isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testAuthenticateFailsWithEmptyUsername() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(null, "koala");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testAuthenticateFailsWithInvalidPassword() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("rod",
				"INVALID_PASSWORD");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testAuthenticateFailsWithInvalidUsernameAndHideUserNotFoundExceptionFalse() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("INVALID_USER",
				"koala");
		DaoAuthenticationProvider provider = createProvider();
		provider.setHideUserNotFoundExceptions(false); // we want
														// UsernameNotFoundExceptions
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testAuthenticateFailsWithInvalidUsernameAndHideUserNotFoundExceptionsWithDefaultOfTrue() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("INVALID_USER",
				"koala");
		DaoAuthenticationProvider provider = createProvider();
		assertThat(provider.isHideUserNotFoundExceptions()).isTrue();
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testAuthenticateFailsWithInvalidUsernameAndChangePasswordEncoder() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("INVALID_USER",
				"koala");
		DaoAuthenticationProvider provider = createProvider();
		assertThat(provider.isHideUserNotFoundExceptions()).isTrue();
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider.authenticate(token));
		provider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testAuthenticateFailsWithMixedCaseUsernameIfDefaultChanged() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("RoD", "koala");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.setUserCache(new MockUserCache());
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testAuthenticates() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("rod", "koala");
		token.setDetails("192.168.0.1");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.setUserCache(new MockUserCache());
		Authentication result = provider.authenticate(token);
		if (!(result instanceof UsernamePasswordAuthenticationToken)) {
			fail("Should have returned instance of UsernamePasswordAuthenticationToken");
		}
		UsernamePasswordAuthenticationToken castResult = (UsernamePasswordAuthenticationToken) result;
		assertThat(castResult.getPrincipal().getClass()).isEqualTo(User.class);
		assertThat(castResult.getCredentials()).isEqualTo("koala");
		assertThat(AuthorityUtils.authorityListToSet(castResult.getAuthorities())).contains("ROLE_ONE", "ROLE_TWO");
		assertThat(castResult.getDetails()).isEqualTo("192.168.0.1");
	}

	@Test
	public void testAuthenticatesASecondTime() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("rod", "koala");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.setUserCache(new MockUserCache());
		Authentication result = provider.authenticate(token);
		if (!(result instanceof UsernamePasswordAuthenticationToken)) {
			fail("Should have returned instance of UsernamePasswordAuthenticationToken");
		}
		// Now try to authenticate with the previous result (with its UserDetails)
		Authentication result2 = provider.authenticate(result);
		if (!(result2 instanceof UsernamePasswordAuthenticationToken)) {
			fail("Should have returned instance of UsernamePasswordAuthenticationToken");
		}
		assertThat(result2.getCredentials()).isEqualTo(result.getCredentials());
	}

	@Test
	public void testAuthenticatesWithForcePrincipalAsString() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("rod", "koala");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.setUserCache(new MockUserCache());
		provider.setForcePrincipalAsString(true);
		Authentication result = provider.authenticate(token);
		if (!(result instanceof UsernamePasswordAuthenticationToken)) {
			fail("Should have returned instance of UsernamePasswordAuthenticationToken");
		}
		UsernamePasswordAuthenticationToken castResult = (UsernamePasswordAuthenticationToken) result;
		assertThat(castResult.getPrincipal().getClass()).isEqualTo(String.class);
		assertThat(castResult.getPrincipal()).isEqualTo("rod");
	}

	@Test
	public void authenticateWhenSuccessAndPasswordManagerThenUpdates() {
		String password = "password";
		String encodedPassword = "encoded";
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("user",
				password);
		PasswordEncoder encoder = mock(PasswordEncoder.class);
		UserDetailsService userDetailsService = mock(UserDetailsService.class);
		UserDetailsPasswordService passwordManager = mock(UserDetailsPasswordService.class);
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(encoder);
		provider.setUserDetailsService(userDetailsService);
		provider.setUserDetailsPasswordService(passwordManager);
		UserDetails user = PasswordEncodedUser.user();
		given(encoder.matches(any(), any())).willReturn(true);
		given(encoder.upgradeEncoding(any())).willReturn(true);
		given(encoder.encode(any())).willReturn(encodedPassword);
		given(userDetailsService.loadUserByUsername(any())).willReturn(user);
		given(passwordManager.updatePassword(any(), any())).willReturn(user);
		Authentication result = provider.authenticate(token);
		verify(encoder).encode(password);
		verify(passwordManager).updatePassword(eq(user), eq(encodedPassword));
	}

	@Test
	public void authenticateWhenBadCredentialsAndPasswordManagerThenNoUpdate() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("user",
				"password");
		PasswordEncoder encoder = mock(PasswordEncoder.class);
		UserDetailsService userDetailsService = mock(UserDetailsService.class);
		UserDetailsPasswordService passwordManager = mock(UserDetailsPasswordService.class);
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(encoder);
		provider.setUserDetailsService(userDetailsService);
		provider.setUserDetailsPasswordService(passwordManager);
		UserDetails user = PasswordEncodedUser.user();
		given(encoder.matches(any(), any())).willReturn(false);
		given(userDetailsService.loadUserByUsername(any())).willReturn(user);
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> provider.authenticate(token));
		verifyNoMoreInteractions(passwordManager);
	}

	@Test
	public void authenticateWhenNotUpgradeAndPasswordManagerThenNoUpdate() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("user",
				"password");
		PasswordEncoder encoder = mock(PasswordEncoder.class);
		UserDetailsService userDetailsService = mock(UserDetailsService.class);
		UserDetailsPasswordService passwordManager = mock(UserDetailsPasswordService.class);
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(encoder);
		provider.setUserDetailsService(userDetailsService);
		provider.setUserDetailsPasswordService(passwordManager);
		UserDetails user = PasswordEncodedUser.user();
		given(encoder.matches(any(), any())).willReturn(true);
		given(encoder.upgradeEncoding(any())).willReturn(false);
		given(userDetailsService.loadUserByUsername(any())).willReturn(user);
		Authentication result = provider.authenticate(token);
		verifyNoMoreInteractions(passwordManager);
	}

	@Test
	public void testDetectsNullBeingReturnedFromAuthenticationDao() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("rod", "koala");
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceReturnsNull());
		assertThatExceptionOfType(AuthenticationServiceException.class).isThrownBy(() -> provider.authenticate(token))
			.withMessage("UserDetailsService returned null, which is an interface contract violation");
	}

	@Test
	public void testGettersSetters() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(new BCryptPasswordEncoder());
		assertThat(provider.getPasswordEncoder().getClass()).isEqualTo(BCryptPasswordEncoder.class);
		provider.setUserCache(new SpringCacheBasedUserCache(mock(Cache.class)));
		assertThat(provider.getUserCache().getClass()).isEqualTo(SpringCacheBasedUserCache.class);
		assertThat(provider.isForcePrincipalAsString()).isFalse();
		provider.setForcePrincipalAsString(true);
		assertThat(provider.isForcePrincipalAsString()).isTrue();
	}

	@Test
	public void testGoesBackToAuthenticationDaoToObtainLatestPasswordIfCachedPasswordSeemsIncorrect() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("rod", "koala");
		MockUserDetailsServiceUserRod authenticationDao = new MockUserDetailsServiceUserRod();
		MockUserCache cache = new MockUserCache();
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(authenticationDao);
		provider.setUserCache(cache);
		// This will work, as password still "koala"
		provider.authenticate(token);
		// Check "rod = koala" ended up in the cache
		assertThat(cache.getUserFromCache("rod").getPassword()).isEqualTo("koala");
		// Now change the password the AuthenticationDao will return
		authenticationDao.setPassword("easternLongNeckTurtle");
		// Now try authentication again, with the new password
		token = UsernamePasswordAuthenticationToken.unauthenticated("rod", "easternLongNeckTurtle");
		provider.authenticate(token);
		// To get this far, the new password was accepted
		// Check the cache was updated
		assertThat(cache.getUserFromCache("rod").getPassword()).isEqualTo("easternLongNeckTurtle");
	}

	@Test
	public void testStartupFailsIfNoAuthenticationDao() throws Exception {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		assertThatIllegalArgumentException().isThrownBy(provider::afterPropertiesSet);
	}

	@Test
	public void testStartupFailsIfNoUserCacheSet() throws Exception {
		DaoAuthenticationProvider provider = createProvider();
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		assertThat(provider.getUserCache().getClass()).isEqualTo(NullUserCache.class);
		provider.setUserCache(null);
		assertThatIllegalArgumentException().isThrownBy(provider::afterPropertiesSet);
	}

	@Test
	public void testStartupSuccess() throws Exception {
		DaoAuthenticationProvider provider = createProvider();
		UserDetailsService userDetailsService = new MockUserDetailsServiceUserRod();
		provider.setUserDetailsService(userDetailsService);
		provider.setUserCache(new MockUserCache());
		assertThat(provider.getUserDetailsService()).isEqualTo(userDetailsService);
		provider.afterPropertiesSet();
	}

	@Test
	public void testSupports() {
		DaoAuthenticationProvider provider = createProvider();
		assertThat(provider.supports(UsernamePasswordAuthenticationToken.class)).isTrue();
		assertThat(!provider.supports(TestingAuthenticationToken.class)).isTrue();
	}

	// SEC-2056
	@Test
	public void testUserNotFoundEncodesPassword() throws Exception {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("missing",
				"koala");
		PasswordEncoder encoder = mock(PasswordEncoder.class);
		given(encoder.encode(anyString())).willReturn("koala");
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setHideUserNotFoundExceptions(false);
		provider.setPasswordEncoder(encoder);
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		provider.afterPropertiesSet();
		assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> provider.authenticate(token));
		// ensure encoder invoked w/ non-null strings since PasswordEncoder impls may fail
		// if encoded password is null
		verify(encoder).matches(isA(String.class), isA(String.class));
	}

	@Test
	public void testUserNotFoundBCryptPasswordEncoder() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("missing",
				"koala");
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setHideUserNotFoundExceptions(false);
		provider.setPasswordEncoder(encoder);
		MockUserDetailsServiceUserRod userDetailsService = new MockUserDetailsServiceUserRod();
		userDetailsService.password = encoder.encode((CharSequence) token.getCredentials());
		provider.setUserDetailsService(userDetailsService);
		assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void testUserNotFoundDefaultEncoder() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("missing",
				null);
		DaoAuthenticationProvider provider = createProvider();
		provider.setHideUserNotFoundExceptions(false);
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> provider.authenticate(token));
	}

	@Test
	public void constructWhenPasswordEncoderProvidedThenSets() {
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(
				NoOpPasswordEncoder.getInstance());
		assertThat(daoAuthenticationProvider.getPasswordEncoder()).isSameAs(NoOpPasswordEncoder.getInstance());
	}

	/**
	 * This is an explicit test for SEC-2056. It is intentionally ignored since this test
	 * is not deterministic and {@link #testUserNotFoundEncodesPassword()} ensures that
	 * SEC-2056 is fixed.
	 */
	public void IGNOREtestSec2056() {
		UsernamePasswordAuthenticationToken foundUser = UsernamePasswordAuthenticationToken.unauthenticated("rod",
				"koala");
		UsernamePasswordAuthenticationToken notFoundUser = UsernamePasswordAuthenticationToken
			.unauthenticated("notFound", "koala");
		PasswordEncoder encoder = new BCryptPasswordEncoder(10, new SecureRandom());
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setHideUserNotFoundExceptions(false);
		provider.setPasswordEncoder(encoder);
		MockUserDetailsServiceUserRod userDetailsService = new MockUserDetailsServiceUserRod();
		userDetailsService.password = encoder.encode((CharSequence) foundUser.getCredentials());
		provider.setUserDetailsService(userDetailsService);
		int sampleSize = 100;
		List<Long> userFoundTimes = new ArrayList<>(sampleSize);
		for (int i = 0; i < sampleSize; i++) {
			long start = System.currentTimeMillis();
			provider.authenticate(foundUser);
			userFoundTimes.add(System.currentTimeMillis() - start);
		}
		List<Long> userNotFoundTimes = new ArrayList<>(sampleSize);
		for (int i = 0; i < sampleSize; i++) {
			long start = System.currentTimeMillis();
			assertThatExceptionOfType(UsernameNotFoundException.class)
				.isThrownBy(() -> provider.authenticate(notFoundUser));
			userNotFoundTimes.add(System.currentTimeMillis() - start);
		}
		double userFoundAvg = avg(userFoundTimes);
		double userNotFoundAvg = avg(userNotFoundTimes);
		assertThat(Math.abs(userNotFoundAvg - userFoundAvg) <= 3)
			.withFailMessage("User not found average " + userNotFoundAvg
					+ " should be within 3ms of user found average " + userFoundAvg)
			.isTrue();
	}

	private double avg(List<Long> counts) {
		return counts.stream().mapToLong(Long::longValue).average().orElse(0);
	}

	@Test
	public void testUserNotFoundNullCredentials() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("missing",
				null);
		PasswordEncoder encoder = mock(PasswordEncoder.class);
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setHideUserNotFoundExceptions(false);
		provider.setPasswordEncoder(encoder);
		provider.setUserDetailsService(new MockUserDetailsServiceUserRod());
		assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> provider.authenticate(token));
		verify(encoder, times(0)).matches(anyString(), anyString());
	}

	@Test
	void authenticateWhenPasswordLeakedThenException() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
		UserDetails user = User.withDefaultPasswordEncoder()
			.username("user")
			.password("password")
			.roles("USER")
			.build();
		provider.setUserDetailsService(withUsers(user));
		provider.setCompromisedPasswordChecker(new TestCompromisedPasswordChecker());
		assertThatExceptionOfType(CompromisedPasswordException.class).isThrownBy(
				() -> provider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("user", "password")))
			.withMessage("The provided password is compromised, please change your password");
	}

	@Test
	void authenticateWhenPasswordNotLeakedThenNoException() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
		UserDetails user = User.withDefaultPasswordEncoder()
			.username("user")
			.password("strongpassword")
			.roles("USER")
			.build();
		provider.setUserDetailsService(withUsers(user));
		provider.setCompromisedPasswordChecker(new TestCompromisedPasswordChecker());
		Authentication authentication = provider
			.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("user", "strongpassword"));
		assertThat(authentication).isNotNull();
	}

	private UserDetailsService withUsers(UserDetails... users) {
		return new InMemoryUserDetailsManager(users);
	}

	private DaoAuthenticationProvider createProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		return provider;
	}

	private class MockUserDetailsServiceReturnsNull implements UserDetailsService {

		@Override
		public UserDetails loadUserByUsername(String username) {
			return null;
		}

	}

	private class MockUserDetailsServiceSimulateBackendError implements UserDetailsService {

		@Override
		public UserDetails loadUserByUsername(String username) {
			throw new DataRetrievalFailureException("This mock simulator is designed to fail");
		}

	}

	private class MockUserDetailsServiceUserRod implements UserDetailsService {

		private String password = "koala";

		@Override
		public UserDetails loadUserByUsername(String username) {
			if ("rod".equals(username)) {
				return new User("rod", this.password, true, true, true, true, ROLES_12);
			}
			throw new UsernameNotFoundException("Could not find: " + username);
		}

		void setPassword(String password) {
			this.password = password;
		}

	}

	private class MockUserDetailsServiceUserPeter implements UserDetailsService {

		@Override
		public UserDetails loadUserByUsername(String username) {
			if ("peter".equals(username)) {
				return new User("peter", "opal", false, true, true, true, ROLES_12);
			}
			throw new UsernameNotFoundException("Could not find: " + username);
		}

	}

	private class MockUserDetailsServiceUserPeterAccountExpired implements UserDetailsService {

		@Override
		public UserDetails loadUserByUsername(String username) {
			if ("peter".equals(username)) {
				return new User("peter", "opal", true, false, true, true, ROLES_12);
			}
			throw new UsernameNotFoundException("Could not find: " + username);
		}

	}

	private class MockUserDetailsServiceUserPeterAccountLocked implements UserDetailsService {

		@Override
		public UserDetails loadUserByUsername(String username) {
			if ("peter".equals(username)) {
				return new User("peter", "opal", true, true, true, false, ROLES_12);
			}
			throw new UsernameNotFoundException("Could not find: " + username);
		}

	}

	private class MockUserDetailsServiceUserPeterCredentialsExpired implements UserDetailsService {

		@Override
		public UserDetails loadUserByUsername(String username) {
			if ("peter".equals(username)) {
				return new User("peter", "opal", true, true, false, true, ROLES_12);
			}
			throw new UsernameNotFoundException("Could not find: " + username);
		}

	}

	private static class TestCompromisedPasswordChecker implements CompromisedPasswordChecker {

		@Override
		public CompromisedPasswordDecision check(String password) {
			if ("password".equals(password)) {
				return new CompromisedPasswordDecision(true);
			}
			return new CompromisedPasswordDecision(false);
		}

	}

}
