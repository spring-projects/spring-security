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

package org.springframework.security.cas.authentication;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.apereo.cas.client.validation.Assertion;
import org.apereo.cas.client.validation.AssertionImpl;
import org.apereo.cas.client.validation.TicketValidator;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link CasAuthenticationProvider}.
 *
 * @author Ben Alex
 * @author Scott Battaglia
 * @author Kim Youngwoong
 */
@SuppressWarnings("unchecked")
public class CasAuthenticationProviderTests {

	private UserDetails makeUserDetails() {
		return new User("user", "password", true, true, true, true,
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
	}

	private UserDetails makeUserDetailsFromAuthoritiesPopulator() {
		return new User("user", "password", true, true, true, true,
				AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B"));
	}

	private ServiceProperties makeServiceProperties() {
		final ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setSendRenew(false);
		serviceProperties.setService("http://test.com");
		return serviceProperties;
	}

	@Test
	public void statefulAuthenticationIsSuccessful() throws Exception {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		StatelessTicketCache cache = new MockStatelessTicketCache();
		cap.setStatelessTicketCache(cache);
		cap.setServiceProperties(makeServiceProperties());
		cap.setTicketValidator(new MockTicketValidator(true));
		cap.afterPropertiesSet();
		CasServiceTicketAuthenticationToken token = CasServiceTicketAuthenticationToken.stateful("ST-123");
		token.setDetails("details");
		Authentication result = cap.authenticate(token);
		// Confirm ST-123 was NOT added to the cache
		assertThat(cache.getByTicketId("ST-456") == null).isTrue();
		if (!(result instanceof CasAuthenticationToken)) {
			fail("Should have returned a CasAuthenticationToken");
		}
		CasAuthenticationToken casResult = (CasAuthenticationToken) result;
		assertThat(casResult.getPrincipal()).isEqualTo(makeUserDetailsFromAuthoritiesPopulator());
		assertThat(casResult.getCredentials()).isEqualTo("ST-123");
		assertThat(casResult.getAuthorities()).contains(new SimpleGrantedAuthority("ROLE_A"));
		assertThat(casResult.getAuthorities()).contains(new SimpleGrantedAuthority("ROLE_B"));
		assertThat(casResult.getKeyHash()).isEqualTo(cap.getKey().hashCode());
		assertThat(casResult.getDetails()).isEqualTo("details");
		// Now confirm the CasAuthenticationToken is automatically re-accepted.
		// To ensure TicketValidator not called again, set it to deliver an exception...
		cap.setTicketValidator(new MockTicketValidator(false));
		Authentication laterResult = cap.authenticate(result);
		assertThat(laterResult).isEqualTo(result);
	}

	@Test
	public void statelessAuthenticationIsSuccessful() throws Exception {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		StatelessTicketCache cache = new MockStatelessTicketCache();
		cap.setStatelessTicketCache(cache);
		cap.setTicketValidator(new MockTicketValidator(true));
		cap.setServiceProperties(makeServiceProperties());
		cap.afterPropertiesSet();
		CasServiceTicketAuthenticationToken token = CasServiceTicketAuthenticationToken.stateless("ST-456");
		token.setDetails("details");
		Authentication result = cap.authenticate(token);
		// Confirm ST-456 was added to the cache
		assertThat(cache.getByTicketId("ST-456") != null).isTrue();
		if (!(result instanceof CasAuthenticationToken)) {
			fail("Should have returned a CasAuthenticationToken");
		}
		assertThat(result.getPrincipal()).isEqualTo(makeUserDetailsFromAuthoritiesPopulator());
		assertThat(result.getCredentials()).isEqualTo("ST-456");
		assertThat(result.getDetails()).isEqualTo("details");
		// Now try to authenticate again. To ensure TicketValidator not
		// called again, set it to deliver an exception...
		cap.setTicketValidator(new MockTicketValidator(false));
		// Previously created CasServiceTicketAuthenticationToken is OK
		Authentication newResult = cap.authenticate(token);
		assertThat(newResult.getPrincipal()).isEqualTo(makeUserDetailsFromAuthoritiesPopulator());
		assertThat(newResult.getCredentials()).isEqualTo("ST-456");
	}

	@Test
	public void authenticateAllNullService() throws Exception {
		String serviceUrl = "https://service/context";
		ServiceAuthenticationDetails details = mock(ServiceAuthenticationDetails.class);
		given(details.getServiceUrl()).willReturn(serviceUrl);
		TicketValidator validator = mock(TicketValidator.class);
		given(validator.validate(any(String.class), any(String.class))).willReturn(new AssertionImpl("rod"));
		ServiceProperties serviceProperties = makeServiceProperties();
		serviceProperties.setAuthenticateAllArtifacts(true);
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		cap.setTicketValidator(validator);
		cap.setServiceProperties(serviceProperties);
		cap.afterPropertiesSet();
		String ticket = "ST-456";
		CasServiceTicketAuthenticationToken token = CasServiceTicketAuthenticationToken.stateless(ticket);
		Authentication result = cap.authenticate(token);
	}

	@Test
	public void authenticateAllAuthenticationIsSuccessful() throws Exception {
		String serviceUrl = "https://service/context";
		ServiceAuthenticationDetails details = mock(ServiceAuthenticationDetails.class);
		given(details.getServiceUrl()).willReturn(serviceUrl);
		TicketValidator validator = mock(TicketValidator.class);
		given(validator.validate(any(String.class), any(String.class))).willReturn(new AssertionImpl("rod"));
		ServiceProperties serviceProperties = makeServiceProperties();
		serviceProperties.setAuthenticateAllArtifacts(true);
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		cap.setTicketValidator(validator);
		cap.setServiceProperties(serviceProperties);
		cap.afterPropertiesSet();
		String ticket = "ST-456";
		CasServiceTicketAuthenticationToken token = CasServiceTicketAuthenticationToken.stateless(ticket);
		Authentication result = cap.authenticate(token);
		verify(validator).validate(ticket, serviceProperties.getService());
		serviceProperties.setAuthenticateAllArtifacts(true);
		result = cap.authenticate(token);
		verify(validator, times(2)).validate(ticket, serviceProperties.getService());
		token.setDetails(details);
		result = cap.authenticate(token);
		verify(validator).validate(ticket, serviceUrl);
		serviceProperties.setAuthenticateAllArtifacts(false);
		serviceProperties.setService(null);
		cap.setServiceProperties(serviceProperties);
		cap.afterPropertiesSet();
		result = cap.authenticate(token);
		verify(validator, times(2)).validate(ticket, serviceUrl);
		token.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
		assertThatIllegalStateException().isThrownBy(() -> cap.authenticate(token));
		cap.setServiceProperties(null);
		cap.afterPropertiesSet();
		assertThatIllegalStateException().isThrownBy(() -> cap.authenticate(token));
	}

	@Test
	public void missingTicketIdIsDetected() throws Exception {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		StatelessTicketCache cache = new MockStatelessTicketCache();
		cap.setStatelessTicketCache(cache);
		cap.setTicketValidator(new MockTicketValidator(true));
		cap.setServiceProperties(makeServiceProperties());
		cap.afterPropertiesSet();
		CasServiceTicketAuthenticationToken token = CasServiceTicketAuthenticationToken.stateful("");
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> cap.authenticate(token));
	}

	@Test
	public void invalidKeyIsDetected() throws Exception {
		final Assertion assertion = new AssertionImpl("test");
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		StatelessTicketCache cache = new MockStatelessTicketCache();
		cap.setStatelessTicketCache(cache);
		cap.setTicketValidator(new MockTicketValidator(true));
		cap.setServiceProperties(makeServiceProperties());
		cap.afterPropertiesSet();
		CasAuthenticationToken token = new CasAuthenticationToken("WRONG_KEY", makeUserDetails(), "credentials",
				AuthorityUtils.createAuthorityList("XX"), makeUserDetails(), assertion);
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> cap.authenticate(token));
	}

	@Test
	public void detectsMissingAuthoritiesPopulator() throws Exception {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setKey("qwerty");
		cap.setStatelessTicketCache(new MockStatelessTicketCache());
		cap.setTicketValidator(new MockTicketValidator(true));
		cap.setServiceProperties(makeServiceProperties());
		assertThatIllegalArgumentException().isThrownBy(() -> cap.afterPropertiesSet());
	}

	@Test
	public void detectsMissingKey() throws Exception {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setStatelessTicketCache(new MockStatelessTicketCache());
		cap.setTicketValidator(new MockTicketValidator(true));
		cap.setServiceProperties(makeServiceProperties());
		assertThatIllegalArgumentException().isThrownBy(() -> cap.afterPropertiesSet());
	}

	@Test
	public void detectsMissingStatelessTicketCache() throws Exception {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		// set this explicitly to null to test failure
		cap.setStatelessTicketCache(null);
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		cap.setTicketValidator(new MockTicketValidator(true));
		cap.setServiceProperties(makeServiceProperties());
		assertThatIllegalArgumentException().isThrownBy(() -> cap.afterPropertiesSet());
	}

	@Test
	public void detectsMissingTicketValidator() throws Exception {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		cap.setStatelessTicketCache(new MockStatelessTicketCache());
		cap.setServiceProperties(makeServiceProperties());
		assertThatIllegalArgumentException().isThrownBy(() -> cap.afterPropertiesSet());
	}

	@Test
	public void gettersAndSettersMatch() throws Exception {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		cap.setStatelessTicketCache(new MockStatelessTicketCache());
		cap.setTicketValidator(new MockTicketValidator(true));
		cap.setServiceProperties(makeServiceProperties());
		cap.afterPropertiesSet();
		// TODO disabled because why do we need to expose this?
		// assertThat(cap.getUserDetailsService() != null).isTrue();
		assertThat(cap.getKey()).isEqualTo("qwerty");
		assertThat(cap.getStatelessTicketCache() != null).isTrue();
		assertThat(cap.getTicketValidator() != null).isTrue();
	}

	@Test
	public void ignoresClassesItDoesNotSupport() throws Exception {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		cap.setStatelessTicketCache(new MockStatelessTicketCache());
		cap.setTicketValidator(new MockTicketValidator(true));
		cap.setServiceProperties(makeServiceProperties());
		cap.afterPropertiesSet();
		TestingAuthenticationToken token = new TestingAuthenticationToken("user", "password", "ROLE_A");
		assertThat(cap.supports(TestingAuthenticationToken.class)).isFalse();
		// Try it anyway
		assertThat(cap.authenticate(token)).isNull();
	}

	@Test
	public void ignoresUsernamePasswordAuthenticationTokensWithoutCasIdentifiersAsPrincipal() throws Exception {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		cap.setStatelessTicketCache(new MockStatelessTicketCache());
		cap.setTicketValidator(new MockTicketValidator(true));
		cap.setServiceProperties(makeServiceProperties());
		cap.afterPropertiesSet();
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("some_normal_user",
				"password", AuthorityUtils.createAuthorityList("ROLE_A"));
		assertThat(cap.authenticate(token)).isNull();
	}

	@Test
	public void supportsRequiredTokens() {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		assertThat(cap.supports(CasServiceTicketAuthenticationToken.class)).isTrue();
		assertThat(cap.supports(CasAuthenticationToken.class)).isTrue();
	}

	@Test
	public void testSetUserDetailsChecker() throws AuthenticationException {
		CasAuthenticationProvider cap = new CasAuthenticationProvider();
		cap.setAuthenticationUserDetailsService(new MockAuthoritiesPopulator());
		cap.setKey("qwerty");
		cap.setTicketValidator(new MockTicketValidator(true));
		cap.setServiceProperties(makeServiceProperties());
		cap.afterPropertiesSet();
		CasServiceTicketAuthenticationToken token = CasServiceTicketAuthenticationToken.stateful("ST-123");

		AtomicInteger checkCount = new AtomicInteger(0);
		UserDetailsChecker userDetailsChecker = new UserDetailsChecker() {
			@Override
			public void check(UserDetails user) {
				checkCount.incrementAndGet();
			}
		};
		cap.setUserDetailsChecker(userDetailsChecker);
		cap.authenticate(token);

		assertThat(checkCount.get()).isEqualTo(1);
	}

	private class MockAuthoritiesPopulator implements AuthenticationUserDetailsService {

		@Override
		public UserDetails loadUserDetails(final Authentication token) throws UsernameNotFoundException {
			return makeUserDetailsFromAuthoritiesPopulator();
		}

	}

	private class MockStatelessTicketCache implements StatelessTicketCache {

		private Map<String, CasAuthenticationToken> cache = new HashMap<>();

		@Override
		public CasAuthenticationToken getByTicketId(String serviceTicket) {
			return this.cache.get(serviceTicket);
		}

		@Override
		public void putTicketInCache(CasAuthenticationToken token) {
			this.cache.put(token.getCredentials().toString(), token);
		}

		@Override
		public void removeTicketFromCache(CasAuthenticationToken token) {
			throw new UnsupportedOperationException("mock method not implemented");
		}

		@Override
		public void removeTicketFromCache(String serviceTicket) {
			throw new UnsupportedOperationException("mock method not implemented");
		}

	}

	private class MockTicketValidator implements TicketValidator {

		private boolean returnTicket;

		MockTicketValidator(boolean returnTicket) {
			this.returnTicket = returnTicket;
		}

		@Override
		public Assertion validate(final String ticket, final String service) {
			if (this.returnTicket) {
				return new AssertionImpl("rod");
			}
			throw new BadCredentialsException("As requested from mock");
		}

	}

}
