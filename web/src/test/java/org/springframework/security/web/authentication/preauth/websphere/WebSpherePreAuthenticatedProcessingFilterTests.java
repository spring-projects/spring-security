/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.authentication.preauth.websphere;

import javax.servlet.FilterChain;

import org.junit.After;
import org.junit.Test;
import org.mockito.stubbing.Answer;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.SimpleAttributes2GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * @author Luke Taylor
 */
public class WebSpherePreAuthenticatedProcessingFilterTests {

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void principalsAndCredentialsAreExtractedCorrectly() throws Exception {
		new WebSpherePreAuthenticatedProcessingFilter();
		WASUsernameAndGroupsExtractor helper = mock(WASUsernameAndGroupsExtractor.class);
		given(helper.getCurrentUserName()).willReturn("jerry");
		WebSpherePreAuthenticatedProcessingFilter filter = new WebSpherePreAuthenticatedProcessingFilter(helper);
		assertThat(filter.getPreAuthenticatedPrincipal(new MockHttpServletRequest())).isEqualTo("jerry");
		assertThat(filter.getPreAuthenticatedCredentials(new MockHttpServletRequest())).isEqualTo("N/A");
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(any(Authentication.class)))
				.willAnswer((Answer<Authentication>) (invocation) -> (Authentication) invocation.getArguments()[0]);
		filter.setAuthenticationManager(am);
		WebSpherePreAuthenticatedWebAuthenticationDetailsSource ads = new WebSpherePreAuthenticatedWebAuthenticationDetailsSource(
				helper);
		ads.setWebSphereGroups2GrantedAuthoritiesMapper(new SimpleAttributes2GrantedAuthoritiesMapper());
		filter.setAuthenticationDetailsSource(ads);
		filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), mock(FilterChain.class));
	}

}
