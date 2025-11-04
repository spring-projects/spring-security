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

package org.springframework.security.config.annotation.authorization;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link EnableMultiFactorAuthentication}.
 *
 * @author Rob Winch
 */
@ExtendWith(SpringExtension.class)
@WebAppConfiguration
@WithMockUser(authorities = FactorGrantedAuthority.PASSWORD_AUTHORITY)
public class EnableMultiFactorAuthenticationFiltersSetTests {

	@Autowired
	private AuthenticationManager manager;

	private TestingAuthenticationToken newAuthn = new TestingAuthenticationToken("user", "password", "ROLE_USER",
			FactorGrantedAuthority.OTT_AUTHORITY);

	@Test
	void preAuthenticationFilter(@Autowired AbstractAuthenticationProcessingFilter filter) throws Exception {
		assertMfaEnabled(filter);
	}

	@Test
	void authenticationFilter(@Autowired AuthenticationFilter filter) throws Exception {
		assertMfaEnabled(filter);
	}

	@Test
	void preAuthnFilter(@Autowired AbstractPreAuthenticatedProcessingFilter filter) throws Exception {
		assertMfaEnabled(filter);
	}

	@Test
	void basicAuthnFilter(@Autowired BasicAuthenticationFilter filter) throws Exception {
		assertMfaEnabled(filter);
	}

	private void assertMfaEnabled(Filter filter) throws Exception {
		given(this.manager.authenticate(any())).willReturn(this.newAuthn);
		MockHttpServletRequest request = MockMvcRequestBuilders.get("/")
			.headers((headers) -> headers.setBasicAuth("u", "p"))
			.buildRequest(new MockServletContext());
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain();
		filter.doFilter(request, response, chain);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(authentication).isNotNull();
		assertThat(authentication.getAuthorities()).extracting(GrantedAuthority::getAuthority)
			.containsExactlyInAnyOrder(FactorGrantedAuthority.OTT_AUTHORITY, FactorGrantedAuthority.PASSWORD_AUTHORITY,
					"ROLE_USER");
	}

	@EnableWebSecurity
	@Configuration
	@EnableMultiFactorAuthentication(
			authorities = { FactorGrantedAuthority.OTT_AUTHORITY, FactorGrantedAuthority.PASSWORD_AUTHORITY })
	static class Config {

		@Bean
		AuthenticationManager authenticationManager() {
			return mock(AuthenticationManager.class);
		}

		@Bean
		static AbstractAuthenticationProcessingFilter authnProcessingFilter(
				AuthenticationManager authenticationManager) {
			AbstractAuthenticationProcessingFilter result = new AbstractAuthenticationProcessingFilter(
					AnyRequestMatcher.INSTANCE, authenticationManager) {
			};
			result.setAuthenticationConverter(new BasicAuthenticationConverter());
			return result;
		}

		@Bean
		static AuthenticationFilter authenticationFilter(AuthenticationManager authenticationManager) {
			return new AuthenticationFilter(authenticationManager, new BasicAuthenticationConverter());
		}

		@Bean
		static AbstractPreAuthenticatedProcessingFilter preAuthenticatedProcessingFilter(
				AuthenticationManager authenticationManager) {
			AbstractPreAuthenticatedProcessingFilter result = new AbstractPreAuthenticatedProcessingFilter() {
				@Override
				protected @Nullable Object getPreAuthenticatedCredentials(HttpServletRequest request) {
					return "password";
				}

				@Override
				protected @Nullable Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
					return "user";
				}
			};
			result.setRequiresAuthenticationRequestMatcher(AnyRequestMatcher.INSTANCE);
			result.setAuthenticationManager(authenticationManager);
			return result;
		}

		@Bean
		static BasicAuthenticationFilter basicAuthenticationFilter(AuthenticationManager authenticationManager) {
			return new BasicAuthenticationFilter(authenticationManager);
		}

	}

}
