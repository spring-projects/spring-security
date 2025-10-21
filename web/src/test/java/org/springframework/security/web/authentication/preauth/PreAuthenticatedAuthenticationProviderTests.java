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

package org.springframework.security.web.authentication.preauth;

import java.util.Collection;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.SecurityAssertions;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author TSARDD
 * @since 18-okt-2007
 */
public class PreAuthenticatedAuthenticationProviderTests {

	@Test
	public final void afterPropertiesSet() {
		PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
		assertThatIllegalArgumentException().isThrownBy(provider::afterPropertiesSet);
	}

	@Test
	public final void authenticateInvalidToken() throws Exception {
		UserDetails ud = new User("dummyUser", "dummyPwd", true, true, true, true, AuthorityUtils.NO_AUTHORITIES);
		PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
		Authentication request = UsernamePasswordAuthenticationToken.unauthenticated("dummyUser", "dummyPwd");
		Authentication result = provider.authenticate(request);
		assertThat(result).isNull();
	}

	@Test
	public final void nullPrincipalReturnsNullAuthentication() {
		PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
		Authentication request = new PreAuthenticatedAuthenticationToken(null, "dummyPwd");
		Authentication result = provider.authenticate(request);
		assertThat(result).isNull();
	}

	@Test
	public final void authenticateKnownUser() throws Exception {
		UserDetails ud = new User("dummyUser", "dummyPwd", true, true, true, true, AuthorityUtils.NO_AUTHORITIES);
		PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
		Authentication request = new PreAuthenticatedAuthenticationToken("dummyUser", "dummyPwd");
		Authentication result = provider.authenticate(request);
		assertThat(result).isNotNull();
		assertThat(ud).isEqualTo(result.getPrincipal());
		// @TODO: Add more asserts?
	}

	@Test
	public final void authenticateIgnoreCredentials() throws Exception {
		UserDetails ud = new User("dummyUser1", "dummyPwd1", true, true, true, true, AuthorityUtils.NO_AUTHORITIES);
		PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
		Authentication request = new PreAuthenticatedAuthenticationToken("dummyUser1", "dummyPwd2");
		Authentication result = provider.authenticate(request);
		assertThat(result).isNotNull();
		assertThat(ud).isEqualTo(result.getPrincipal());
		// @TODO: Add more asserts?
	}

	@Test
	public final void authenticateUnknownUserThrowsException() throws Exception {
		UserDetails ud = new User("dummyUser1", "dummyPwd", true, true, true, true, AuthorityUtils.NO_AUTHORITIES);
		PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
		Authentication request = new PreAuthenticatedAuthenticationToken("dummyUser2", "dummyPwd");
		assertThatExceptionOfType(UsernameNotFoundException.class).isThrownBy(() -> provider.authenticate(request));
	}

	@Test
	void authenticateWhenSuccessThenIssuesFactor() {
		UserDetails ud = PasswordEncodedUser.user();
		PreAuthenticatedAuthenticationProvider provider = getProvider(ud);
		Supplier<Collection<GrantedAuthority>> authorities = mock(Supplier.class);
		given(authorities.get()).willReturn(AuthorityUtils.createAuthorityList("FACTOR"));
		provider.setGrantedAuthoritySupplier(authorities);
		Authentication request = new PreAuthenticatedAuthenticationToken(ud.getUsername(), ud.getPassword());
		Authentication result = provider.authenticate(request);
		SecurityAssertions.assertThat(result).hasAuthority("FACTOR");
		verify(authorities).get();
	}

	@Test
	public final void supportsArbitraryObject() throws Exception {
		PreAuthenticatedAuthenticationProvider provider = getProvider(null);
		assertThat(provider.supports(Authentication.class)).isFalse();
	}

	@Test
	public final void supportsPreAuthenticatedAuthenticationToken() throws Exception {
		PreAuthenticatedAuthenticationProvider provider = getProvider(null);
		assertThat(provider.supports(PreAuthenticatedAuthenticationToken.class)).isTrue();
	}

	@Test
	public void getSetOrder() throws Exception {
		PreAuthenticatedAuthenticationProvider provider = getProvider(null);
		provider.setOrder(333);
		assertThat(333).isEqualTo(provider.getOrder());
	}

	private PreAuthenticatedAuthenticationProvider getProvider(UserDetails aUserDetails) {
		PreAuthenticatedAuthenticationProvider result = new PreAuthenticatedAuthenticationProvider();
		result.setPreAuthenticatedUserDetailsService(getPreAuthenticatedUserDetailsService(aUserDetails));
		result.afterPropertiesSet();
		return result;
	}

	private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> getPreAuthenticatedUserDetailsService(
			final UserDetails aUserDetails) {
		return (token) -> {
			if (aUserDetails != null && aUserDetails.getUsername().equals(token.getName())) {
				return aUserDetails;
			}
			throw new UsernameNotFoundException("notfound");
		};
	}

}
