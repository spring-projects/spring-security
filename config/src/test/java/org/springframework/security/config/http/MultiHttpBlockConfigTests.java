/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.web.bind.annotation.GetMapping;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests scenarios with multiple &lt;http&gt; elements.
 *
 * @author Luke Taylor
 */
public class MultiHttpBlockConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/MultiHttpBlockConfigTests";

	@Autowired
	MockMvc mvc;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	public void requestWhenUsingMutuallyExclusiveHttpElementsThenIsRoutedAccordingly() throws Exception {
		this.spring.configLocations(this.xml("DistinctHttpElements")).autowire();
		this.mvc.perform(MockMvcRequestBuilders.get("/first").with(httpBasic("user", "password")))
				.andExpect(status().isOk());
		this.mvc.perform(post("/second/login").param("username", "user").param("password", "password").with(csrf()))
				.andExpect(status().isFound()).andExpect(redirectedUrl("/"));
	}

	@Test
	public void configureWhenUsingDuplicateHttpElementsThenThrowsWiringException() {
		assertThatCode(() -> this.spring.configLocations(this.xml("IdenticalHttpElements")).autowire())
				.isInstanceOf(BeanCreationException.class).hasCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void configureWhenUsingIndenticallyPatternedHttpElementsThenThrowsWiringException() {
		assertThatCode(() -> this.spring.configLocations(this.xml("IdenticallyPatternedHttpElements")).autowire())
				.isInstanceOf(BeanCreationException.class).hasCauseInstanceOf(IllegalArgumentException.class);
	}

	/**
	 * SEC-1937
	 */
	@Test
	public void requestWhenTargettingAuthenticationManagersToCorrespondingHttpElementsThenAuthenticationProceeds()
			throws Exception {
		this.spring.configLocations(this.xml("Sec1937")).autowire();
		this.mvc.perform(get("/first").with(httpBasic("first", "password")).with(csrf())).andExpect(status().isOk());
		this.mvc.perform(post("/second/login").param("username", "second").param("password", "password").with(csrf()))
				.andExpect(redirectedUrl("/"));
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	@Controller
	static class BasicController {

		@GetMapping("/first")
		String first() {
			return "ok";
		}

	}

}
