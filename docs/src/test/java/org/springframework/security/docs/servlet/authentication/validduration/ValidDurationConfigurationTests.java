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

package org.springframework.security.docs.servlet.authentication.validduration;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.docs.servlet.authentication.servletx509config.CustomX509Configuration;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests {@link CustomX509Configuration}.
 *
 * @author Rob Winch
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@TestExecutionListeners(WithSecurityContextTestExecutionListener.class)
public class ValidDurationConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mockMvc;

	@Test
	void adminWhenExpiredThenRequired() throws Exception {
		this.spring.register(
				ValidDurationConfiguration.class, Http200Controller.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/admin/").with(admin(Duration.ofMinutes(31))))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrlPattern("http://localhost/login?*"));
		// @formatter:on
	}

	@Test
	void adminWhenNotExpiredThenOk() throws Exception {
		this.spring.register(
				ValidDurationConfiguration.class, Http200Controller.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/admin/").with(admin(Duration.ofMinutes(29))))
				.andExpect(status().isOk());
		// @formatter:on
	}

	@Test
	void settingsWhenExpiredThenRequired() throws Exception {
		this.spring.register(
				ValidDurationConfiguration.class, Http200Controller.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/user/settings").with(user(Duration.ofMinutes(61))))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrlPattern("http://localhost/login?*"));
		// @formatter:on
	}

	@Test
	void settingsWhenNotExpiredThenOk() throws Exception {
		this.spring.register(
				ValidDurationConfiguration.class, Http200Controller.class).autowire();
		// @formatter:off
		this.mockMvc.perform(get("/user/settings").with(user(Duration.ofMinutes(59))))
				.andExpect(status().isOk());
		// @formatter:on
	}

	private static RequestPostProcessor admin(Duration sinceAuthn) {
		return authn("admin", sinceAuthn);
	}

	private static RequestPostProcessor user(Duration sinceAuthn) {
		return authn("user", sinceAuthn);
	}

	private static RequestPostProcessor authn(String username, Duration sinceAuthn) {
		Instant issuedAt = Instant.now().minus(sinceAuthn);
		FactorGrantedAuthority factor = FactorGrantedAuthority
				.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
				.issuedAt(issuedAt)
				.build();
		String role = username.toUpperCase();
		TestingAuthenticationToken authn = new TestingAuthenticationToken(username, "",
				factor, new SimpleGrantedAuthority("ROLE_" + role));
		return authentication(authn);
	}

	@RestController
	static class Http200Controller {
		@GetMapping("/**")
		String ok() {
			return "ok";
		}
	}
}
