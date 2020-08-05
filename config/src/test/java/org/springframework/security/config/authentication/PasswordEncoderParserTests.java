/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.config.authentication;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class PasswordEncoderParserTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mockMvc;

	@Test
	public void passwordEncoderDefaultsToDelegatingPasswordEncoder() throws Exception {
		this.spring.configLocations(
				"classpath:org/springframework/security/config/authentication/PasswordEncoderParserTests-default.xml")
				.mockMvcAfterSpringSecurityOk().autowire();

		this.mockMvc.perform(get("/").with(httpBasic("user", "password"))).andExpect(status().isOk());
	}

	@Test
	public void passwordEncoderDefaultsToPasswordEncoderBean() throws Exception {
		this.spring.configLocations(
				"classpath:org/springframework/security/config/authentication/PasswordEncoderParserTests-bean.xml")
				.mockMvcAfterSpringSecurityOk().autowire();

		this.mockMvc.perform(get("/").with(httpBasic("user", "password"))).andExpect(status().isOk());
	}

}
