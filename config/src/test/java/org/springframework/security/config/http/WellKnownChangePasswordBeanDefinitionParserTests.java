/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.http;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link WellKnownChangePasswordBeanDefinitionParser}.
 *
 * @author Evgeniy Cheban
 */
@ExtendWith(SpringTestContextExtension.class)
public class WellKnownChangePasswordBeanDefinitionParserTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/WellKnownChangePasswordBeanDefinitionParserTests";

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void whenChangePasswordPageNotSetThenDefaultChangePasswordPageUsed() throws Exception {
		this.spring.configLocations(xml("DefaultChangePasswordPage")).autowire();

		this.mvc.perform(get("/.well-known/change-password")).andExpect(status().isFound())
				.andExpect(redirectedUrl("/change-password"));
	}

	@Test
	public void whenChangePasswordPageSetThenSpecifiedChangePasswordPageUsed() throws Exception {
		this.spring.configLocations(xml("CustomChangePasswordPage")).autowire();

		this.mvc.perform(get("/.well-known/change-password")).andExpect(status().isFound())
				.andExpect(redirectedUrl("/custom-change-password-page"));
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

}
