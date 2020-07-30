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

package org.springframework.security.test.web.servlet.request;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.TestOAuth2AuthenticatedPrincipals;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.opaqueToken;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link SecurityMockMvcRequestPostProcessors#opaqueToken()}
 *
 * @author Josh Cummings
 * @since 5.3
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class SecurityMockMvcRequestPostProcessorsOpaqueTokenTests {

	@Autowired
	WebApplicationContext context;

	MockMvc mvc;

	@Before
	public void setup() {
		// @formatter:off
		this.mvc = MockMvcBuilders
			.webAppContextSetup(this.context)
			.apply(springSecurity())
			.build();
		// @formatter:on
	}

	@Test
	public void opaqueTokenWhenUsingDefaultsThenProducesDefaultAuthentication() throws Exception {

		this.mvc.perform(get("/name").with(opaqueToken())).andExpect(content().string("user"));
		this.mvc.perform(get("/admin/scopes").with(opaqueToken())).andExpect(status().isForbidden());
	}

	@Test
	public void opaqueTokenWhenAttributeSpecifiedThenUserHasAttribute() throws Exception {
		this.mvc.perform(
				get("/opaque-token/iss").with(opaqueToken().attributes((a) -> a.put("iss", "https://idp.example.org"))))
				.andExpect(content().string("https://idp.example.org"));
	}

	@Test
	public void opaqueTokenWhenPrincipalSpecifiedThenAuthenticationHasPrincipal() throws Exception {
		Collection authorities = Collections.singleton(new SimpleGrantedAuthority("SCOPE_read"));
		OAuth2AuthenticatedPrincipal principal = mock(OAuth2AuthenticatedPrincipal.class);
		given(principal.getName()).willReturn("ben");
		given(principal.getAuthorities()).willReturn(authorities);

		this.mvc.perform(get("/name").with(opaqueToken().principal(principal))).andExpect(content().string("ben"));
	}

	// gh-7800
	@Test
	public void opaqueTokenWhenPrincipalSpecifiedThenLastCalledTakesPrecedence() throws Exception {
		OAuth2AuthenticatedPrincipal principal = TestOAuth2AuthenticatedPrincipals
				.active((a) -> a.put("scope", "user"));

		this.mvc.perform(get("/opaque-token/sub")
				.with(opaqueToken().attributes((a) -> a.put("sub", "foo")).principal(principal)))
				.andExpect(status().isOk()).andExpect(content().string((String) principal.getAttribute("sub")));
		this.mvc.perform(get("/opaque-token/sub")
				.with(opaqueToken().principal(principal).attributes((a) -> a.put("sub", "bar"))))
				.andExpect(content().string("bar"));
	}

	@EnableWebSecurity
	@EnableWebMvc
	static class OAuth2LoginConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.mvcMatchers("/admin/**").hasAuthority("SCOPE_admin")
					.anyRequest().hasAuthority("SCOPE_read")
					.and()
				.oauth2ResourceServer()
					.opaqueToken()
						.introspector(mock(OpaqueTokenIntrospector.class));
			// @formatter:on
		}

		@RestController
		static class PrincipalController {

			@GetMapping("/name")
			String name(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal) {
				return principal.getName();
			}

			@GetMapping("/opaque-token/{attribute}")
			String tokenAttribute(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal principal,
					@PathVariable("attribute") String attribute) {

				return principal.getAttribute(attribute);
			}

			@GetMapping("/admin/scopes")
			List<String> scopes(
					@AuthenticationPrincipal(expression = "authorities") Collection<GrantedAuthority> authorities) {

				return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
			}

		}

	}

}
