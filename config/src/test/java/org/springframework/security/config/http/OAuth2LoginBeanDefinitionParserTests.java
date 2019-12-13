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
package org.springframework.security.config.http;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link OAuth2LoginBeanDefinitionParser}.
 *
 * @author
 */
public class OAuth2LoginBeanDefinitionParserTests {
	private static final String CONFIG_LOCATION_PREFIX =
			"classpath:org/springframework/security/config/http/OAuth2LoginBeanDefinitionParserTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestWhenSingleClientRegistrationThenAutoRedirect() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration")).autowire();

		this.mvc.perform(get("/"))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrlPattern("/oauth2/authorization/google-login"));
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}
}
