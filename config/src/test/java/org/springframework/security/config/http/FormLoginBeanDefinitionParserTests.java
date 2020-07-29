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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.web.WebAttributes;
import org.springframework.test.web.servlet.MockMvc;

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
public class FormLoginBeanDefinitionParserTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/FormLoginBeanDefinitionParserTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void getLoginWhenAutoConfigThenShowsDefaultLoginPage() throws Exception {

		this.spring.configLocations(this.xml("Simple")).autowire();

		String expectedContent = "<!DOCTYPE html>\n" + "<html lang=\"en\">\n" + "  <head>\n"
				+ "    <meta charset=\"utf-8\">\n"
				+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
				+ "    <meta name=\"description\" content=\"\">\n" + "    <meta name=\"author\" content=\"\">\n"
				+ "    <title>Please sign in</title>\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "  </head>\n" + "  <body>\n" + "     <div class=\"container\">\n"
				+ "      <form class=\"form-signin\" method=\"post\" action=\"/login\">\n"
				+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n" + "        <p>\n"
				+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"username\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n" + "        <p>\n"
				+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
				+ "          <input type=\"password\" id=\"password\" name=\"password\" class=\"form-control\" placeholder=\"Password\" required>\n"
				+ "        </p>\n"
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
				+ "      </form>\n" + "</div>\n" + "</body></html>";

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

		String expectedContent = "<!DOCTYPE html>\n" + "<html lang=\"en\">\n" + "  <head>\n"
				+ "    <meta charset=\"utf-8\">\n"
				+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
				+ "    <meta name=\"description\" content=\"\">\n" + "    <meta name=\"author\" content=\"\">\n"
				+ "    <title>Please sign in</title>\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "  </head>\n" + "  <body>\n" + "     <div class=\"container\">\n"
				+ "      <form class=\"form-signin\" method=\"post\" action=\"/signin\">\n"
				+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n" + "        <p>\n"
				+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"custom_user\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n" + "        <p>\n"
				+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
				+ "          <input type=\"password\" id=\"password\" name=\"custom_pass\" class=\"form-control\" placeholder=\"Password\" required>\n"
				+ "        </p>\n"
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
				+ "      </form>\n" + "</div>\n" + "</body></html>";

		this.mvc.perform(get("/login")).andExpect(content().string(expectedContent));

		this.mvc.perform(get("/logout")).andExpect(status().is3xxRedirection());
	}

	@Test
	public void getLoginWhenConfiguredForOpenIdThenLoginPageReflects() throws Exception {

		this.spring.configLocations(this.xml("WithOpenId")).autowire();

		String expectedContent = "<!DOCTYPE html>\n" + "<html lang=\"en\">\n" + "  <head>\n"
				+ "    <meta charset=\"utf-8\">\n"
				+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
				+ "    <meta name=\"description\" content=\"\">\n" + "    <meta name=\"author\" content=\"\">\n"
				+ "    <title>Please sign in</title>\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "  </head>\n" + "  <body>\n" + "     <div class=\"container\">\n"
				+ "      <form class=\"form-signin\" method=\"post\" action=\"/login\">\n"
				+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n" + "        <p>\n"
				+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"username\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n" + "        <p>\n"
				+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
				+ "          <input type=\"password\" id=\"password\" name=\"password\" class=\"form-control\" placeholder=\"Password\" required>\n"
				+ "        </p>\n"
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
				+ "      </form>\n"
				+ "      <form name=\"oidf\" class=\"form-signin\" method=\"post\" action=\"/login/openid\">\n"
				+ "        <h2 class=\"form-signin-heading\">Login with OpenID Identity</h2>\n" + "        <p>\n"
				+ "          <label for=\"username\" class=\"sr-only\">Identity</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"openid_identifier\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n"
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
				+ "      </form>\n" + "</div>\n" + "</body></html>";

		this.mvc.perform(get("/login")).andExpect(content().string(expectedContent));
	}

	@Test
	public void getLoginWhenConfiguredForOpenIdWithCustomAttributesThenLoginPageReflects() throws Exception {

		this.spring.configLocations(this.xml("WithOpenIdCustomAttributes")).autowire();

		String expectedContent = "<!DOCTYPE html>\n" + "<html lang=\"en\">\n" + "  <head>\n"
				+ "    <meta charset=\"utf-8\">\n"
				+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
				+ "    <meta name=\"description\" content=\"\">\n" + "    <meta name=\"author\" content=\"\">\n"
				+ "    <title>Please sign in</title>\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "  </head>\n" + "  <body>\n" + "     <div class=\"container\">\n"
				+ "      <form class=\"form-signin\" method=\"post\" action=\"/login\">\n"
				+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n" + "        <p>\n"
				+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"username\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n" + "        <p>\n"
				+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
				+ "          <input type=\"password\" id=\"password\" name=\"password\" class=\"form-control\" placeholder=\"Password\" required>\n"
				+ "        </p>\n"
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
				+ "      </form>\n"
				+ "      <form name=\"oidf\" class=\"form-signin\" method=\"post\" action=\"/signin\">\n"
				+ "        <h2 class=\"form-signin-heading\">Login with OpenID Identity</h2>\n" + "        <p>\n"
				+ "          <label for=\"username\" class=\"sr-only\">Identity</label>\n"
				+ "          <input type=\"text\" id=\"username\" name=\"openid_identifier\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
				+ "        </p>\n"
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
				+ "      </form>\n" + "</div>\n" + "</body></html>";

		this.mvc.perform(get("/login")).andExpect(content().string(expectedContent));
	}

	@Test
	public void failedLoginWhenConfiguredWithCustomAuthenticationFailureThenForwardsAccordingly() throws Exception {

		this.spring.configLocations(this.xml("WithAuthenticationFailureForwardUrl")).autowire();

		this.mvc.perform(post("/login").param("username", "bob").param("password", "invalidpassword"))
				.andExpect(status().isOk()).andExpect(forwardedUrl("/failure_forward_url"))
				.andExpect(request().attribute(WebAttributes.AUTHENTICATION_EXCEPTION, not(nullValue())));
	}

	@Test
	public void successfulLoginWhenConfiguredWithCustomAuthenticationSuccessThenForwardsAccordingly() throws Exception {

		this.spring.configLocations(this.xml("WithAuthenticationSuccessForwardUrl")).autowire();

		this.mvc.perform(post("/login").param("username", "user").param("password", "password"))
				.andExpect(status().isOk()).andExpect(forwardedUrl("/success_forward_url"));
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

}
