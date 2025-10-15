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

package org.springframework.security.web.access;

import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorityAuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.FactorAuthorizationDecision;
import org.springframework.security.authorization.RequiredFactor;
import org.springframework.security.authorization.RequiredFactorError;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class DelegatingMissingAuthorityAccessDeniedHandlerTests {

	DelegatingMissingAuthorityAccessDeniedHandler.Builder builder;

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	@Mock
	AuthenticationEntryPoint factorEntryPoint;

	@Mock
	AccessDeniedHandler defaultAccessDeniedHandler;

	@BeforeEach
	void setUp() {
		this.builder = DelegatingMissingAuthorityAccessDeniedHandler.builder();
		this.builder.addEntryPointFor(this.factorEntryPoint, "FACTOR");
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
	}

	@Test
	void whenKnownAuthorityThenCommences() throws Exception {
		AccessDeniedHandler accessDeniedHandler = this.builder.build();
		accessDeniedHandler.handle(this.request, this.response, missingAuthorities("FACTOR"));
		verify(this.factorEntryPoint).commence(any(), any(), any());
	}

	@Test
	void whenUnknownAuthorityThenDefaultCommences() throws Exception {
		DelegatingMissingAuthorityAccessDeniedHandler accessDeniedHandler = this.builder.build();
		accessDeniedHandler.setDefaultAccessDeniedHandler(this.defaultAccessDeniedHandler);
		accessDeniedHandler.handle(this.request, this.response, missingAuthorities("ROLE_USER"));
		verify(this.defaultAccessDeniedHandler).handle(any(), any(), any());
		verifyNoInteractions(this.factorEntryPoint);
	}

	@Test
	void whenNoAuthoritiesFoundThenDefaultCommences() throws Exception {
		DelegatingMissingAuthorityAccessDeniedHandler accessDeniedHandler = this.builder.build();
		accessDeniedHandler.setDefaultAccessDeniedHandler(this.defaultAccessDeniedHandler);
		accessDeniedHandler.handle(this.request, this.response, new AccessDeniedException("access denied"));
		verify(this.defaultAccessDeniedHandler).handle(any(), any(), any());
	}

	@Test
	void whenMultipleAuthoritiesThenFirstMatchCommences() throws Exception {
		AuthenticationEntryPoint passwordEntryPoint = mock(AuthenticationEntryPoint.class);
		this.builder.addEntryPointFor(passwordEntryPoint, "PASSWORD");
		AccessDeniedHandler accessDeniedHandler = this.builder.build();
		accessDeniedHandler.handle(this.request, this.response, missingAuthorities("PASSWORD", "FACTOR"));
		verify(passwordEntryPoint).commence(any(), any(), any());
		accessDeniedHandler.handle(this.request, this.response, missingAuthorities("FACTOR", "PASSWORD"));
		verify(this.factorEntryPoint).commence(any(), any(), any());
	}

	@Test
	void whenCustomRequestCacheThenUses() throws Exception {
		RequestCache requestCache = mock(RequestCache.class);
		DelegatingMissingAuthorityAccessDeniedHandler accessDeniedHandler = this.builder.build();
		accessDeniedHandler.setRequestCache(requestCache);
		accessDeniedHandler.handle(this.request, this.response, missingAuthorities("FACTOR"));
		verify(requestCache).saveRequest(any(), any());
		verify(this.factorEntryPoint).commence(any(), any(), any());
	}

	@Test
	void whenKnownAuthorityButNoRequestMatchThenCommences() throws Exception {
		AuthenticationEntryPoint passwordEntryPoint = mock(AuthenticationEntryPoint.class);
		RequestMatcher xhr = new RequestHeaderRequestMatcher("X-Requested-With");
		this.builder.addEntryPointFor((ep) -> ep.addEntryPointFor(passwordEntryPoint, xhr), "PASSWORD");
		AccessDeniedHandler accessDeniedHandler = this.builder.build();
		accessDeniedHandler.handle(this.request, this.response, missingAuthorities("PASSWORD"));
		verify(passwordEntryPoint).commence(any(), any(), any());
	}

	@Test
	void whenMultipleEntryPointsThenFirstRequestMatchCommences() throws Exception {
		AuthenticationEntryPoint basicPasswordEntryPoint = mock(AuthenticationEntryPoint.class);
		AuthenticationEntryPoint formPasswordEntryPoint = mock(AuthenticationEntryPoint.class);
		RequestMatcher xhr = new RequestHeaderRequestMatcher("X-Requested-With");
		this.builder.addEntryPointFor(
				(ep) -> ep.addEntryPointFor(basicPasswordEntryPoint, xhr).defaultEntryPoint(formPasswordEntryPoint),
				"PASSWORD");
		AccessDeniedHandler accessDeniedHandler = this.builder.build();
		accessDeniedHandler.handle(this.request, this.response, missingAuthorities("PASSWORD"));
		verify(formPasswordEntryPoint).commence(any(), any(), any());
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("X-Requested-With", "XmlHttpRequest");
		accessDeniedHandler.handle(request, this.response, missingAuthorities("PASSWORD"));
		verify(basicPasswordEntryPoint).commence(any(), any(), any());
	}

	// gh-18000
	@Test
	void whenMultipleFactorErrorsThenPropagatesAll() throws Exception {
		AccessDeniedHandler accessDeniedHandler = this.builder.build();
		accessDeniedHandler.handle(this.request, this.response, missingFactors("FACTOR", "PASSWORD"));
		verify(this.factorEntryPoint).commence(any(), any(), any());
		Object attribute = this.request.getAttribute(WebAttributes.REQUIRED_FACTOR_ERRORS);
		assertThat(attribute).isInstanceOf(Collection.class);
		assertThat((Collection<?>) attribute).hasSize(2);
	}

	AuthorizationDeniedException missingAuthorities(String... authorities) {
		Collection<GrantedAuthority> granted = AuthorityUtils.createAuthorityList(authorities);
		AuthorityAuthorizationDecision decision = new AuthorityAuthorizationDecision(false, granted);
		return new AuthorizationDeniedException("access denied", decision);
	}

	AuthorizationDeniedException missingFactors(String... factors) {
		List<RequiredFactorError> errors = Stream.of(factors)
			.map((f) -> RequiredFactorError.createMissing(RequiredFactor.withAuthority(f).build()))
			.toList();
		FactorAuthorizationDecision decision = new FactorAuthorizationDecision(errors);
		return new AuthorizationDeniedException("access denied", decision);
	}

}
