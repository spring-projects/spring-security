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
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.ConfigurableWebApplicationContext;

import javax.servlet.ServletRegistration;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
public class InterceptUrlConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/InterceptUrlConfigTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	/**
	 * sec-2256
	 */
	@Test
	public void requestWhenMethodIsSpecifiedThenItIsNotGivenPriority() throws Exception {

		this.spring.configLocations(this.xml("Sec2256")).autowire();

		this.mvc.perform(post("/path").with(httpBasic("user", "password"))).andExpect(status().isOk());

		this.mvc.perform(get("/path").with(httpBasic("user", "password"))).andExpect(status().isOk());
	}

	/**
	 * sec-2355
	 */
	@Test
	public void requestWhenUsingPatchThenAuthorizesRequestsAccordingly() throws Exception {

		this.spring.configLocations(this.xml("PatchMethod")).autowire();

		this.mvc.perform(get("/path").with(httpBasic("user", "password"))).andExpect(status().isOk());

		this.mvc.perform(patch("/path").with(httpBasic("user", "password"))).andExpect(status().isForbidden());

		this.mvc.perform(patch("/path").with(httpBasic("admin", "password"))).andExpect(status().isOk());

	}

	@Test
	public void requestWhenUsingHasAnyRoleThenAuthorizesRequestsAccordingly() throws Exception {

		this.spring.configLocations(this.xml("HasAnyRole")).autowire();

		this.mvc.perform(get("/path").with(httpBasic("user", "password"))).andExpect(status().isOk());

		this.mvc.perform(get("/path").with(httpBasic("admin", "password"))).andExpect(status().isForbidden());
	}

	/**
	 * sec-2059
	 */
	@Test
	public void requestWhenUsingPathVariablesThenAuthorizesRequestsAccordingly() throws Exception {

		this.spring.configLocations(this.xml("PathVariables")).autowire();

		this.mvc.perform(get("/path/user/path").with(httpBasic("user", "password"))).andExpect(status().isOk());

		this.mvc.perform(get("/path/otheruser/path").with(httpBasic("user", "password")))
				.andExpect(status().isForbidden());

		this.mvc.perform(get("/path").with(httpBasic("user", "password"))).andExpect(status().isForbidden());
	}

	/**
	 * gh-3786
	 */
	@Test
	public void requestWhenUsingCamelCasePathVariablesThenAuthorizesRequestsAccordingly() throws Exception {

		this.spring.configLocations(this.xml("CamelCasePathVariables")).autowire();

		this.mvc.perform(get("/path/user/path").with(httpBasic("user", "password"))).andExpect(status().isOk());

		this.mvc.perform(get("/path/otheruser/path").with(httpBasic("user", "password")))
				.andExpect(status().isForbidden());

		this.mvc.perform(get("/PATH/user/path").with(httpBasic("user", "password"))).andExpect(status().isForbidden());
	}

	/**
	 * sec-2059
	 */
	@Test
	public void requestWhenUsingPathVariablesAndTypeConversionThenAuthorizesRequestsAccordingly() throws Exception {

		this.spring.configLocations(this.xml("TypeConversionPathVariables")).autowire();

		this.mvc.perform(get("/path/1/path").with(httpBasic("user", "password"))).andExpect(status().isOk());

		this.mvc.perform(get("/path/2/path").with(httpBasic("user", "password"))).andExpect(status().isForbidden());

	}

	@Test
	public void requestWhenUsingMvcMatchersThenAuthorizesRequestsAccordingly() throws Exception {

		this.spring.configLocations(this.xml("MvcMatchers")).autowire();

		this.mvc.perform(get("/path")).andExpect(status().isUnauthorized());

		this.mvc.perform(get("/path.html")).andExpect(status().isUnauthorized());

		this.mvc.perform(get("/path/")).andExpect(status().isUnauthorized());
	}

	@Test
	public void requestWhenUsingMvcMatchersAndPathVariablesThenAuthorizesRequestsAccordingly() throws Exception {

		this.spring.configLocations(this.xml("MvcMatchersPathVariables")).autowire();

		this.mvc.perform(get("/path/user/path").with(httpBasic("user", "password"))).andExpect(status().isOk());

		this.mvc.perform(get("/path/otheruser/path").with(httpBasic("user", "password")))
				.andExpect(status().isForbidden());

		this.mvc.perform(get("/PATH/user/path").with(httpBasic("user", "password"))).andExpect(status().isForbidden());
	}

	@Test
	public void requestWhenUsingMvcMatchersAndServletPathThenAuthorizesRequestsAccordingly() throws Exception {

		this.spring.configLocations(this.xml("MvcMatchersServletPath")).autowire();

		MockServletContext servletContext = mockServletContext("/spring");
		ConfigurableWebApplicationContext context = (ConfigurableWebApplicationContext) this.spring.getContext();
		context.setServletContext(servletContext);

		this.mvc.perform(get("/spring/path").servletPath("/spring")).andExpect(status().isUnauthorized());

		this.mvc.perform(get("/spring/path.html").servletPath("/spring")).andExpect(status().isUnauthorized());

		this.mvc.perform(get("/spring/path/").servletPath("/spring")).andExpect(status().isUnauthorized());

	}

	@Test
	public void configureWhenUsingAntMatcherAndServletPathThenThrowsException() {
		assertThatCode(() -> this.spring.configLocations(this.xml("AntMatcherServletPath")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void configureWhenUsingRegexMatcherAndServletPathThenThrowsException() {
		assertThatCode(() -> this.spring.configLocations(this.xml("RegexMatcherServletPath")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void configureWhenUsingCiRegexMatcherAndServletPathThenThrowsException() {
		assertThatCode(() -> this.spring.configLocations(this.xml("CiRegexMatcherServletPath")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class);
	}

	@Test
	public void configureWhenUsingDefaultMatcherAndServletPathThenThrowsException() {
		assertThatCode(() -> this.spring.configLocations(this.xml("DefaultMatcherServletPath")).autowire())
				.isInstanceOf(BeanDefinitionParsingException.class);
	}

	@RestController
	static class PathController {

		@RequestMapping("/path")
		public String path() {
			return "path";
		}

		@RequestMapping("/path/{un}/path")
		public String path(@PathVariable("un") String name) {
			return name;
		}

	}

	public static class Id {

		public boolean isOne(int i) {
			return i == 1;
		}

	}

	private MockServletContext mockServletContext(String servletPath) {
		MockServletContext servletContext = spy(new MockServletContext());
		final ServletRegistration registration = mock(ServletRegistration.class);
		when(registration.getMappings()).thenReturn(Collections.singleton(servletPath));
		Answer<Map<String, ? extends ServletRegistration>> answer = invocation -> Collections.singletonMap("spring",
				registration);
		when(servletContext.getServletRegistrations()).thenAnswer(answer);
		return servletContext;
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

}
