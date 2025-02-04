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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Josh Cummings
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class PlaceHolderAndELConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/PlaceHolderAndELConfigTests";

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void getWhenUsingPlaceholderThenUnsecuredPatternCorrectlyConfigured() throws Exception {
		System.setProperty("pattern.nofilters", "/unsecured");
		this.spring.configLocations(this.xml("UnsecuredPattern")).autowire();
		// @formatter:off
		this.mvc.perform(get("/unsecured"))
				.andExpect(status().isOk());
		// @formatter:on
	}

	/**
	 * SEC-1201
	 */
	@Test
	public void loginWhenUsingPlaceholderThenInterceptUrlsAndFormLoginWorks() throws Exception {
		System.setProperty("secure.Url", "/secured");
		System.setProperty("secure.role", "ROLE_NUNYA");
		System.setProperty("login.page", "/loginPage");
		System.setProperty("default.target", "/defaultTarget");
		System.setProperty("auth.failure", "/authFailure");
		this.spring.configLocations(this.xml("InterceptUrlAndFormLogin")).autowire();
		// login-page setting
		// @formatter:off
		this.mvc.perform(get("/secured"))
				.andExpect(redirectedUrl("http://localhost/loginPage"));
		// login-processing-url setting
		// default-target-url setting
		this.mvc.perform(post("/loginPage").param("username", "user").param("password", "password"))
				.andExpect(redirectedUrl("/defaultTarget"));
		// authentication-failure-url setting
		this.mvc.perform(post("/loginPage").param("username", "user").param("password", "wrong"))
				.andExpect(redirectedUrl("/authFailure"));
		// @formatter:on
	}

	/**
	 * SEC-1309
	 */
	@Test
	public void loginWhenUsingSpELThenInterceptUrlsAndFormLoginWorks() throws Exception {
		System.setProperty("secure.url", "/secured");
		System.setProperty("secure.role", "ROLE_NUNYA");
		System.setProperty("login.page", "/loginPage");
		System.setProperty("default.target", "/defaultTarget");
		System.setProperty("auth.failure", "/authFailure");
		this.spring.configLocations(this.xml("InterceptUrlAndFormLoginWithSpEL")).autowire();
		// login-page setting
		// @formatter:off
		this.mvc.perform(get("/secured"))
				.andExpect(redirectedUrl("http://localhost/loginPage"));
		// login-processing-url setting
		// default-target-url setting
		this.mvc.perform(post("/loginPage").param("username", "user").param("password", "password"))
				.andExpect(redirectedUrl("/defaultTarget"));
		// authentication-failure-url setting
		this.mvc.perform(post("/loginPage").param("username", "user").param("password", "wrong"))
				.andExpect(redirectedUrl("/authFailure"));
		// @formatter:on
	}

	@Test
	@WithMockUser
	public void requestWhenUsingPlaceholderOrSpELThenPortMapperWorks() throws Exception {
		System.setProperty("http", "9080");
		System.setProperty("https", "9443");
		this.spring.configLocations(this.xml("PortMapping")).autowire();
		// @formatter:off
		this.mvc.perform(get("http://localhost:9080/secured"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("https://localhost:9443/secured"));
		this.mvc.perform(get("https://localhost:9443/unsecured"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost:9080/unsecured"));
		// @formatter:on
	}

	@Test
	@WithMockUser
	public void requestWhenUsingPlaceholderThenRequiresChannelWorks() throws Exception {
		System.setProperty("secure.url", "/secured");
		System.setProperty("required.channel", "https");
		this.spring.configLocations(this.xml("RequiresChannel")).autowire();
		// @formatter:off
		this.mvc.perform(get("http://localhost/secured"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("https://localhost/secured"));
		// @formatter:on
	}

	@Test
	@WithMockUser
	public void requestWhenUsingPlaceholderThenAccessDeniedPageWorks() throws Exception {
		System.setProperty("accessDenied", "/go-away");
		this.spring.configLocations(this.xml("AccessDeniedPage")).autowire();
		// @formatter:off
		this.mvc.perform(get("/secured"))
				.andExpect(forwardedUrl("/go-away"));
		// @formatter:on
	}

	@Test
	@WithMockUser
	public void requestWhenUsingSpELThenAccessDeniedPageWorks() throws Exception {
		this.spring.configLocations(this.xml("AccessDeniedPageWithSpEL")).autowire();
		// @formatter:off
		this.mvc.perform(get("/secured"))
				.andExpect(forwardedUrl("/go-away"));
		// @formatter:on
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	@RestController
	static class SimpleController {

		@GetMapping("/unsecured")
		String unsecured() {
			return "unsecured";
		}

		@GetMapping("/secured")
		String secured() {
			return "secured";
		}

	}

}
