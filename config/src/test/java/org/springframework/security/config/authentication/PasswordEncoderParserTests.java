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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith(SpringTestContextExtension.class)
public class PasswordEncoderParserTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mockMvc;

	@Test
	public void passwordEncoderDefaultsToDelegatingPasswordEncoder() throws Exception {
		this.spring.configLocations(
				"classpath:org/springframework/security/config/authentication/PasswordEncoderParserTests-default.xml")
			.mockMvcAfterSpringSecurityOk()
			.autowire();
		// @formatter:off
		this.mockMvc.perform(get("/").with(httpBasic("user", "password")))
				.andExpect(status().isOk());
		// @formatter:on
	}

	@Test
	public void passwordEncoderDefaultsToPasswordEncoderBean() throws Exception {
		this.spring
			.configLocations(
					"classpath:org/springframework/security/config/authentication/PasswordEncoderParserTests-bean.xml")
			.mockMvcAfterSpringSecurityOk()
			.autowire();
		// @formatter:off
		this.mockMvc.perform(get("/").with(httpBasic("user", "password")))
				.andExpect(status().isOk());
		// @formatter:on
	}

	@Test
	void testCreatePasswordEncoderBeanDefinition() throws Exception {
		String hash = "bcrypt";
		Class<?> expectedBeanClass = BCryptPasswordEncoder.class;

		BeanDefinition beanDefinition = PasswordEncoderParser.createPasswordEncoderBeanDefinition(hash);

		Class<?> actualBeanClass = Class.forName(beanDefinition.getBeanClassName());
		assertThat(actualBeanClass).isEqualTo(expectedBeanClass);
	}

}
