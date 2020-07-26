/*
 * Copyright 2002-2013 the original author or authors.
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

import javax.servlet.http.HttpServletRequest;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Tests to verify that all the functionality of &lt;http-firewall&gt; attributes is
 * present
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
public class NamespaceHttpFirewallTests {

	@Rule
	public final SpringTestRule rule = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void requestWhenPathContainsDoubleDotsThenBehaviorMatchesNamespace() {
		this.rule.register(HttpFirewallConfig.class).autowire();
		assertThatCode(() -> this.mvc.perform(get("/public/../private/"))).isInstanceOf(RequestRejectedException.class);
	}

	@Test
	public void requestWithCustomFirewallThenBehaviorMatchesNamespace() {
		this.rule.register(CustomHttpFirewallConfig.class).autowire();
		assertThatCode(() -> this.mvc.perform(get("/").param("deny", "true")))
				.isInstanceOf(RequestRejectedException.class);
	}

	@Test
	public void requestWithCustomFirewallBeanThenBehaviorMatchesNamespace() {
		this.rule.register(CustomHttpFirewallBeanConfig.class).autowire();
		assertThatCode(() -> this.mvc.perform(get("/").param("deny", "true")))
				.isInstanceOf(RequestRejectedException.class);
	}

	@EnableWebSecurity
	static class HttpFirewallConfig {

	}

	@EnableWebSecurity
	static class CustomHttpFirewallConfig extends WebSecurityConfigurerAdapter {

		@Override
		public void configure(WebSecurity web) {
			web.httpFirewall(new CustomHttpFirewall());
		}

	}

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
