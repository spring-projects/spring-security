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

	//@formatter:off
	public static final String EXPECTED_HTML_HEAD = "  <head>\n"
			+ "    <meta charset=\"utf-8\">\n"
			+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
			+ "    <meta name=\"description\" content=\"\">\n"
			+ "    <meta name=\"author\" content=\"\">\n"
			+ "    <title>Please sign in</title>\n"
			+ "    <style>\n"
			+ "    /* General layout */\n"
			+ "    body {\n"
			+ "      font-family: system-ui, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;\n"
			+ "      background-color: #eee;\n"
			+ "      padding: 40px 0;\n"
			+ "      margin: 0;\n"
			+ "      line-height: 1.5;\n"
			+ "    }\n"
			+ "    \n"
			+ "    h2 {\n"
			+ "      margin-top: 0;\n"
			+ "      margin-bottom: 0.5rem;\n"
			+ "      font-size: 2rem;\n"
			+ "      font-weight: 500;\n"
			+ "      line-height: 2rem;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .content {\n"
			+ "      margin-right: auto;\n"
			+ "      margin-left: auto;\n"
			+ "      padding-right: 15px;\n"
			+ "      padding-left: 15px;\n"
			+ "      width: 100%;\n"
			+ "      box-sizing: border-box;\n"
			+ "    }\n"
			+ "    \n"
			+ "    @media (min-width: 800px) {\n"
			+ "      .content {\n"
			+ "        max-width: 760px;\n"
			+ "      }\n"
			+ "    }\n"
			+ "    \n"
			+ "    /* Components */\n"
			+ "    a,\n"
			+ "    a:visited {\n"
			+ "      text-decoration: none;\n"
			+ "      color: #06f;\n"
			+ "    }\n"
			+ "    \n"
			+ "    a:hover {\n"
			+ "      text-decoration: underline;\n"
			+ "      color: #003c97;\n"
			+ "    }\n"
			+ "    \n"
			+ "    input[type=\"text\"],\n"
			+ "    input[type=\"password\"] {\n"
			+ "      height: auto;\n"
			+ "      width: 100%;\n"
			+ "      font-size: 1rem;\n"
			+ "      padding: 0.5rem;\n"
			+ "      box-sizing: border-box;\n"
			+ "    }\n"
			+ "    \n"
			+ "    button {\n"
			+ "      padding: 0.5rem 1rem;\n"
			+ "      font-size: 1.25rem;\n"
			+ "      line-height: 1.5;\n"
			+ "      border: none;\n"
			+ "      border-radius: 0.1rem;\n"
			+ "      width: 100%;\n"
			+ "    }\n"
			+ "    \n"
			+ "    button.primary {\n"
			+ "      color: #fff;\n"
			+ "      background-color: #06f;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .alert {\n"
			+ "      padding: 0.75rem 1rem;\n"
			+ "      margin-bottom: 1rem;\n"
			+ "      line-height: 1.5;\n"
			+ "      border-radius: 0.1rem;\n"
			+ "      width: 100%;\n"
			+ "      box-sizing: border-box;\n"
			+ "      border-width: 1px;\n"
			+ "      border-style: solid;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .alert.alert-danger {\n"
			+ "      color: #6b1922;\n"
			+ "      background-color: #f7d5d7;\n"
			+ "      border-color: #eab6bb;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .alert.alert-success {\n"
			+ "      color: #145222;\n"
			+ "      background-color: #d1f0d9;\n"
			+ "      border-color: #c2ebcb;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .screenreader {\n"
			+ "      position: absolute;\n"
			+ "      clip: rect(0 0 0 0);\n"
			+ "      height: 1px;\n"
			+ "      width: 1px;\n"
			+ "      padding: 0;\n"
			+ "      border: 0;\n"
			+ "      overflow: hidden;\n"
			+ "    }\n"
			+ "    \n"
			+ "    table {\n"
			+ "      width: 100%;\n"
			+ "      max-width: 100%;\n"
			+ "      margin-bottom: 2rem;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .table-striped tr:nth-of-type(2n + 1) {\n"
			+ "      background-color: #e1e1e1;\n"
			+ "    }\n"
			+ "    \n"
			+ "    td {\n"
			+ "      padding: 0.75rem;\n"
			+ "      vertical-align: top;\n"
			+ "    }\n"
			+ "    \n"
			+ "    /* Login / logout layouts */\n"
			+ "    .login-form,\n"
			+ "    .logout-form {\n"
			+ "      max-width: 340px;\n"
			+ "      padding: 0 15px 15px 15px;\n"
			+ "      margin: 0 auto 2rem auto;\n"
			+ "      box-sizing: border-box;\n"
			+ "    }\n"
			+ "    </style>\n"
			+ "  </head>\n";
	//@formatter:on

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void getLoginWhenAutoConfigThenShowsDefaultLoginPage() throws Exception {
		this.spring.configLocations(this.xml("Simple")).autowire();
		// @formatter:off
		String expectedContent = "<!DOCTYPE html>\n"
				+ "<html lang=\"en\">\n"
				+ EXPECTED_HTML_HEAD
				+ "  <body>\n"
				+ "     <div class=\"content\">\n"
				+ "      <form class=\"login-form\" method=\"post\" action=\"/login\">\n"
				+ "        <h2>Please sign in</h2>\n"
				+ "        <p>\n"
				+ "          <label for=\"username\" class=\"screenreader\">Username</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"username\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n"
				+ "        <p>\n"
				+ "          <label for=\"password\" class=\"screenreader\">Password</label>\n"
				+ "          <input type=\"password\" id=\"password\" name=\"password\" placeholder=\"Password\" required>\n"
				+ "        </p>\n"
				+ "        <button type=\"submit\" class=\"primary\">Sign in</button>\n"
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
				+ EXPECTED_HTML_HEAD
				+ "  <body>\n"
				+ "     <div class=\"content\">\n"
				+ "      <form class=\"login-form\" method=\"post\" action=\"/signin\">\n"
				+ "        <h2>Please sign in</h2>\n"
				+ "        <p>\n"
				+ "          <label for=\"username\" class=\"screenreader\">Username</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"custom_user\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n"
				+ "        <p>\n"
				+ "          <label for=\"password\" class=\"screenreader\">Password</label>\n"
				+ "          <input type=\"password\" id=\"password\" name=\"custom_pass\" placeholder=\"Password\" required>\n"
				+ "        </p>\n"
				+ "        <button type=\"submit\" class=\"primary\">Sign in</button>\n"
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
