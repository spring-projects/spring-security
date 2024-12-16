/*
 * Copyright 2002-2024 the original author or authors.
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
		String expectedContent = """
				<!DOCTYPE html>
				<html lang="en">
				  <head>
				    <meta charset="utf-8">
				    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
				    <meta name="description" content="">
				    <meta name="author" content="">
				    <title>Please sign in</title>
				    <link href="/default-ui.css" rel="stylesheet" />
				  </head>
				  <body>
				    <div class="content">
				      <form class="login-form" method="post" action="/login">
				        <h2>Please sign in</h2>

				        <p>
				          <label for="username" class="screenreader">Username</label>
				          <input type="text" id="username" name="username" placeholder="Username" required autofocus>
				        </p>
				        <p>
				          <label for="password" class="screenreader">Password</label>
				          <input type="password" id="password" name="password" placeholder="Password" required>
				        </p>


				        <button type="submit" class="primary">Sign in</button>
				      </form>



				    </div>
				  </body>
				</html>""";
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

		String expectedContent = """
				<!DOCTYPE html>
				<html lang="en">
				  <head>
				    <meta charset="utf-8">
				    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
				    <meta name="description" content="">
				    <meta name="author" content="">
				    <title>Please sign in</title>
				    <link href="/default-ui.css" rel="stylesheet" />
				  </head>
				  <body>
				    <div class="content">
				      <form class="login-form" method="post" action="/signin">
				        <h2>Please sign in</h2>

				        <p>
				          <label for="username" class="screenreader">Username</label>
				          <input type="text" id="username" name="custom_user" placeholder="Username" required autofocus>
				        </p>
				        <p>
				          <label for="password" class="screenreader">Password</label>
				          <input type="password" id="password" name="custom_pass" placeholder="Password" required>
				        </p>


				        <button type="submit" class="primary">Sign in</button>
				      </form>



				    </div>
				  </body>
				</html>""";
		this.mvc.perform(get("/login")).andExpect(content().string(expectedContent));
		this.mvc.perform(get("/logout")).andExpect(status().is3xxRedirection());
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
