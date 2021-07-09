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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
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
@ExtendWith(SpringTestContextExtension.class)
public class MultiHttpBlockConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/MultiHttpBlockConfigTests";

	@Autowired
	MockMvc mvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void requestWhenUsingMutuallyExclusiveHttpElementsThenIsRoutedAccordingly() throws Exception {
		this.spring.configLocations(this.xml("DistinctHttpElements")).autowire();
		// @formatter:off
		this.mvc.perform(get("/first").with(httpBasic("user", "password")))
				.andExpect(status().isOk());
		MockHttpServletRequestBuilder formLoginRequest = post("/second/login")
				.param("username", "user")
				.param("password", "password")
				.with(csrf());
		this.mvc.perform(formLoginRequest)
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/"));
		// @formatter:on
	}

	@Test
	public void configureWhenUsingDuplicateHttpElementsThenThrowsWiringException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.configLocations(this.xml("IdenticalHttpElements")).autowire())
				.withCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void configureWhenUsingIndenticallyPatternedHttpElementsThenThrowsWiringException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.configLocations(this.xml("IdenticallyPatternedHttpElements")).autowire())
				.withCauseInstanceOf(IllegalArgumentException.class);
	}

	/**
	 * SEC-1937
	 */
	@Test
	public void requestWhenTargettingAuthenticationManagersToCorrespondingHttpElementsThenAuthenticationProceeds()
			throws Exception {
		this.spring.configLocations(this.xml("Sec1937")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder basicLoginRequest = get("/first")
				.with(httpBasic("first", "password"))
				.with(csrf());
		this.mvc.perform(basicLoginRequest)
				.andExpect(status().isOk());
		MockHttpServletRequestBuilder formLoginRequest = post("/second/login")
				.param("username", "second")
				.param("password", "password")
				.with(csrf());
		this.mvc.perform(formLoginRequest)
				.andExpect(redirectedUrl("/"));
		// @formatter:on
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
