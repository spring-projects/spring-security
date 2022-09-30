/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of &lt;http-firewall&gt; attributes is
 * present
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class NamespaceHttpFirewallTests {

	public final SpringTestContext rule = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void requestWhenPathContainsDoubleDotsThenBehaviorMatchesNamespace() throws Exception {
		this.rule.register(HttpFirewallConfig.class).autowire();
		this.mvc.perform(get("/public/../private/")).andExpect(status().isBadRequest());
	}

	@Test
	public void requestWithCustomFirewallThenBehaviorMatchesNamespace() throws Exception {
		this.rule.register(CustomHttpFirewallConfig.class).autowire();
		this.mvc.perform(get("/").param("deny", "true")).andExpect(status().isBadRequest());
	}

	@Test
	public void requestWithCustomFirewallBeanThenBehaviorMatchesNamespace() throws Exception {
		this.rule.register(CustomHttpFirewallBeanConfig.class).autowire();
		this.mvc.perform(get("/").param("deny", "true")).andExpect(status().isBadRequest());
	}

	@Configuration
	@EnableWebSecurity
	static class HttpFirewallConfig {

	}

	@Configuration
	@EnableWebSecurity
	static class CustomHttpFirewallConfig {

		@Bean
		WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.httpFirewall(new CustomHttpFirewall());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomHttpFirewallBeanConfig {

		@Bean
		HttpFirewall firewall() {
			return new CustomHttpFirewall();
		}

	}

	static class CustomHttpFirewall extends DefaultHttpFirewall {

		@Override
		public FirewalledRequest getFirewalledRequest(HttpServletRequest request) throws RequestRejectedException {
			if (request.getParameter("deny") != null) {
				throw new RequestRejectedException("custom rejection");
			}
			return super.getFirewalledRequest(request);
		}

	}

}
