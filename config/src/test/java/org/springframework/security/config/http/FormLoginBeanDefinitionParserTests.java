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
import org.springframework.security.web.WebAttributes;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Luke Taylor
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class FormLoginBeanDefinitionParserTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/FormLoginBeanDefinitionParserTests";

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void getLoginWhenAutoConfigThenShowsDefaultLoginPage() throws Exception {
		this.spring.configLocations(this.xml("Simple")).autowire();
		// @formatter:off
		String expectedContent = "<!DOCTYPE html>\n"
				+ "<html lang=\"en\">\n"
				+ "  <head>\n"
				+ "    <meta charset=\"utf-8\">\n"
				+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
				+ "    <meta name=\"description\" content=\"\">\n"
				+ "    <meta name=\"author\" content=\"\">\n"
				+ "    <title>Please sign in</title>\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "  </head>\n"
				+ "  <body>\n"
				+ "     <div class=\"container\">\n"
				+ "      <form class=\"form-signin\" method=\"post\" action=\"/login\">\n"
				+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n"
				+ "        <p>\n"
				+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"username\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n"
				+ "        <p>\n"
				+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
				+ "          <input type=\"password\" id=\"password\" name=\"password\" class=\"form-control\" placeholder=\"Password\" required>\n"
				+ "        </p>\n"
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
				+ "      </form>\n"
				+ "</div>\n"
				+ "</body></html>";
		// @formatter:on
		this.mvc.perform(get("/login")).andExpect(content().string(expectedContent));
	}

	@Test
	public void getLogoutWhenAutoConfigThenShowsDefaultLogoutPage() throws Exception {
		this.spring.configLocations(this.xml("AutoConfig")).autowire();
		this.mvc.perform(get("/logout")).andExpect(content().string(containsString("action=\"/logout\"")));
	}

	@Test
	public void getLoginWhenConfiguredWithCustomAttributesThenLoginPageReflects() throws Exception {
		this.spring.configLocations(this.xml("WithCustomAttributes")).autowire();
		// @formatter:off
		String expectedContent = "<!DOCTYPE html>\n"
				+ "<html lang=\"en\">\n"
				+ "  <head>\n"
				+ "    <meta charset=\"utf-8\">\n"
				+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
				+ "    <meta name=\"description\" content=\"\">\n"
				+ "    <meta name=\"author\" content=\"\">\n"
				+ "    <title>Please sign in</title>\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "  </head>\n"
				+ "  <body>\n"
				+ "     <div class=\"container\">\n"
				+ "      <form class=\"form-signin\" method=\"post\" action=\"/signin\">\n"
				+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n"
				+ "        <p>\n"
				+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"custom_user\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n"
				+ "        <p>\n"
				+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
				+ "          <input type=\"password\" id=\"password\" name=\"custom_pass\" class=\"form-control\" placeholder=\"Password\" required>\n"
				+ "        </p>\n"
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
				+ "      </form>\n"
				+ "</div>\n"
				+ "</body></html>";
		this.mvc.perform(get("/login"))
				.andExpect(content().string(expectedContent));
		this.mvc.perform(get("/logout"))
				.andExpect(status().is3xxRedirection());
		// @formatter:on
	}

	@Test
	public void failedLoginWhenConfiguredWithCustomAuthenticationFailureThenForwardsAccordingly() throws Exception {
		this.spring.configLocations(this.xml("WithAuthenticationFailureForwardUrl")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "bob")
				.param("password", "invalidpassword");
		this.mvc.perform(loginRequest)
				.andExpect(status().isOk())
				.andExpect(forwardedUrl("/failure_forward_url"))
				.andExpect(request().attribute(WebAttributes.AUTHENTICATION_EXCEPTION, not(nullValue())));
		// @formatter:on
	}

	@Test
	public void successfulLoginWhenConfiguredWithCustomAuthenticationSuccessThenForwardsAccordingly() throws Exception {
		this.spring.configLocations(this.xml("WithAuthenticationSuccessForwardUrl")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password");
		this.mvc.perform(loginRequest)
				.andExpect(status().isOk())
				.andExpect(forwardedUrl("/success_forward_url"));
		// @formatter:on
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

}
