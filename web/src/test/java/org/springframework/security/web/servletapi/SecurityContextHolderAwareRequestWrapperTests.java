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

package org.springframework.security.web.servletapi;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link SecurityContextHolderAwareRequestWrapper}.
 *
 * @author Ben Alex
 */
public class SecurityContextHolderAwareRequestWrapperTests {

	@BeforeEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testCorrectOperationWithStringBasedPrincipal() {
		Authentication auth = new TestingAuthenticationToken("rod", "koala", "ROLE_FOO");
		SecurityContextHolder.getContext().setAuthentication(auth);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/");
		SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request, "");
		assertThat(wrapper.getRemoteUser()).isEqualTo("rod");
		assertThat(wrapper.isUserInRole("ROLE_FOO")).isTrue();
		assertThat(wrapper.isUserInRole("ROLE_NOT_GRANTED")).isFalse();
		assertThat(wrapper.getUserPrincipal()).isEqualTo(auth);
	}

	@Test
	public void testUseOfRolePrefixMeansItIsntNeededWhenCallngIsUserInRole() {
		Authentication auth = new TestingAuthenticationToken("rod", "koala", "ROLE_FOO");
		SecurityContextHolder.getContext().setAuthentication(auth);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/");
		SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request,
				"ROLE_");
		assertThat(wrapper.isUserInRole("FOO")).isTrue();
	}

	@Test
	public void testCorrectOperationWithUserDetailsBasedPrincipal() {
		Authentication auth = new TestingAuthenticationToken(
				new User("rodAsUserDetails", "koala", true, true, true, true, AuthorityUtils.NO_AUTHORITIES), "koala",
				"ROLE_HELLO", "ROLE_FOOBAR");
		SecurityContextHolder.getContext().setAuthentication(auth);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/");
		SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request, "");
		assertThat(wrapper.getRemoteUser()).isEqualTo("rodAsUserDetails");
		assertThat(wrapper.isUserInRole("ROLE_FOO")).isFalse();
		assertThat(wrapper.isUserInRole("ROLE_NOT_GRANTED")).isFalse();
		assertThat(wrapper.isUserInRole("ROLE_FOOBAR")).isTrue();
		assertThat(wrapper.isUserInRole("ROLE_HELLO")).isTrue();
		assertThat(wrapper.getUserPrincipal()).isEqualTo(auth);
	}

	@Test
	public void testRoleIsntHeldIfAuthenticationIsNull() {
		SecurityContextHolder.getContext().setAuthentication(null);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/");
		SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request, "");
		assertThat(wrapper.getRemoteUser()).isNull();
		assertThat(wrapper.isUserInRole("ROLE_ANY")).isFalse();
		assertThat(wrapper.getUserPrincipal()).isNull();
	}

	@Test
	public void testRolesArentHeldIfAuthenticationPrincipalIsNull() {
		Authentication auth = new TestingAuthenticationToken(null, "koala", "ROLE_HELLO", "ROLE_FOOBAR");
		SecurityContextHolder.getContext().setAuthentication(auth);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/");
		SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request, "");
		assertThat(wrapper.getRemoteUser()).isNull();
		assertThat(wrapper.isUserInRole("ROLE_HELLO")).isFalse(); // principal is null, so
																	// reject
		assertThat(wrapper.isUserInRole("ROLE_FOOBAR")).isFalse(); // principal is null,
																	// so reject
		assertThat(wrapper.getUserPrincipal()).isNull();
	}

	@Test
	public void testRolePrefix() {
		Authentication auth = new TestingAuthenticationToken("user", "koala", "ROLE_HELLO", "ROLE_FOOBAR");
		SecurityContextHolder.getContext().setAuthentication(auth);
		MockHttpServletRequest request = new MockHttpServletRequest();
		SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request,
				"ROLE_");
		assertThat(wrapper.isUserInRole("HELLO")).isTrue();
		assertThat(wrapper.isUserInRole("FOOBAR")).isTrue();
	}

	// SEC-3020
	@Test
	public void testRolePrefixNotAppliedIfRoleStartsWith() {
		Authentication auth = new TestingAuthenticationToken("user", "koala", "ROLE_HELLO", "ROLE_FOOBAR");
		SecurityContextHolder.getContext().setAuthentication(auth);
		MockHttpServletRequest request = new MockHttpServletRequest();
		SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request,
				"ROLE_");
		assertThat(wrapper.isUserInRole("ROLE_HELLO")).isTrue();
		assertThat(wrapper.isUserInRole("ROLE_FOOBAR")).isTrue();
	}

	@Test
	public void testGetRemoteUserStringWithAuthenticatedPrincipal() {
		String username = "authPrincipalUsername";
		AuthenticatedPrincipal principal = mock(AuthenticatedPrincipal.class);
		given(principal.getName()).willReturn(username);
		Authentication auth = new TestingAuthenticationToken(principal, "user");
		SecurityContextHolder.getContext().setAuthentication(auth);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/");
		SecurityContextHolderAwareRequestWrapper wrapper = new SecurityContextHolderAwareRequestWrapper(request, "");
		assertThat(wrapper.getRemoteUser()).isEqualTo(username);
		verify(principal, times(1)).getName();
	}

}
