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
package org.springframework.security.test.web.servlet.setup;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.users.AuthenticationTestConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import javax.servlet.Filter;

import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 */
@RunWith(SpringRunner.class)
@WebAppConfiguration
public class SecurityMockMvcConfigurersTests {
	@Autowired
	WebApplicationContext wac;

	Filter noOpFilter = mock(Filter.class);

	/**
	 * Since noOpFilter is first does not continue the chain, security will not be invoked and the status should be OK
	 *
	 * @throws Exception
	 */
	@Test
	public void applySpringSecurityWhenAddFilterFirstThenFilterFirst() throws Exception {
		MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(this.wac)
			.addFilters(this.noOpFilter)
			.apply(springSecurity())
			.build();

		mockMvc.perform(get("/"))
			.andExpect(status().isOk());
	}

	/**
	 * Since noOpFilter is second security will be invoked and the status will be not OK. We know this because if noOpFilter
	 * were first security would not be invoked sincet noOpFilter does not continue the FilterChain
	 * @throws Exception
	 */
	@Test
	public void applySpringSecurityWhenAddFilterSecondThenSecurityFirst() throws Exception {
		MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(this.wac)
				.apply(springSecurity())
				.addFilters(this.noOpFilter)
				.build();

		mockMvc.perform(get("/"))
				.andExpect(status().is4xxClientError());
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	@Import(AuthenticationTestConfiguration.class)
	static class Config {}
}
