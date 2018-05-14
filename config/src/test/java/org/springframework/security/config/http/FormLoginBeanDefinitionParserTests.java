/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


/**
 *
 * @author Luke Taylor
 * @author Josh Cummings
 */
public class FormLoginBeanDefinitionParserTests {
	private static final String CONFIG_LOCATION_PREFIX =
			"classpath:org/springframework/security/config/http/FormLoginBeanDefinitionParserTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void getLoginWhenAutoConfigThenShowsDefaultLoginPage()
		throws Exception {

		this.spring.configLocations(this.xml("Simple")).autowire();

		String expectedContent =
				"<html><head><title>Login Page</title></head><body onload='document.f.username.focus();'>\n" +
				"<h3>Login with Username and Password</h3><form name='f' action='/login' method='POST'>\n" +
				"<table>\n" +
				"	<tr><td>User:</td><td><input type='text' name='username' value=''></td></tr>\n" +
				"	<tr><td>Password:</td><td><input type='password' name='password'/></td></tr>\n" +
				"	<tr><td colspan='2'><input name=\"submit\" type=\"submit\" value=\"Login\"/></td></tr>\n" +
				"</table>\n" +
				"</form></body></html>";

		this.mvc.perform(get("/login")).andExpect(content().string(expectedContent));
	}

	@Test
	public void getLoginWhenConfiguredWithCustomAttributesThenLoginPageReflects()
			throws Exception {

		this.spring.configLocations(this.xml("WithCustomAttributes")).autowire();

		String expectedContent =
				"<html><head><title>Login Page</title></head><body onload='document.f.custom_user.focus();'>\n" +
						"<h3>Login with Username and Password</h3><form name='f' action='/signin' method='POST'>\n" +
						"<table>\n" +
						"	<tr><td>User:</td><td><input type='text' name='custom_user' value=''></td></tr>\n" +
						"	<tr><td>Password:</td><td><input type='password' name='custom_pass'/></td></tr>\n" +
						"	<tr><td colspan='2'><input name=\"submit\" type=\"submit\" value=\"Login\"/></td></tr>\n" +
						"</table>\n" +
						"</form></body></html>";

		this.mvc.perform(get("/login")).andExpect(content().string(expectedContent));
	}

	@Test
	public void getLoginWhenConfiguredForOpenIdThenLoginPageReflects()
		throws Exception {

		this.spring.configLocations(this.xml("WithOpenId")).autowire();

		String expectedContent =
				"<html><head><title>Login Page</title></head><body onload='document.f.username.focus();'>\n" +
				"<h3>Login with Username and Password</h3><form name='f' action='/login' method='POST'>\n" +
				"<table>\n" +
				"	<tr><td>User:</td><td><input type='text' name='username' value=''></td></tr>\n" +
				"	<tr><td>Password:</td><td><input type='password' name='password'/></td></tr>\n" +
				"	<tr><td colspan='2'><input name=\"submit\" type=\"submit\" value=\"Login\"/></td></tr>\n" +
				"</table>\n" +
				"</form><h3>Login with OpenID Identity</h3><form name='oidf' action='/login/openid' method='POST'>\n" +
				"<table>\n" +
				"	<tr><td>Identity:</td><td><input type='text' size='30' name='openid_identifier'/></td></tr>\n" +
				"	<tr><td colspan='2'><input name=\"submit\" type=\"submit\" value=\"Login\"/></td></tr>\n" +
				"</table>\n" +
				"</form></body></html>";

		this.mvc.perform(get("/login")).andExpect(content().string(expectedContent));
	}

	@Test
	public void getLoginWhenConfiguredForOpenIdWithCustomAttributesThenLoginPageReflects()
			throws Exception {

		this.spring.configLocations(this.xml("WithOpenIdCustomAttributes")).autowire();

		String expectedContent =
				"<html><head><title>Login Page</title></head><body onload='document.f.username.focus();'>\n" +
						"<h3>Login with Username and Password</h3><form name='f' action='/login' method='POST'>\n" +
						"<table>\n" +
						"	<tr><td>User:</td><td><input type='text' name='username' value=''></td></tr>\n" +
						"	<tr><td>Password:</td><td><input type='password' name='password'/></td></tr>\n" +
						"	<tr><td colspan='2'><input name=\"submit\" type=\"submit\" value=\"Login\"/></td></tr>\n" +
						"</table>\n" +
						"</form><h3>Login with OpenID Identity</h3><form name='oidf' action='/signin' method='POST'>\n" +
						"<table>\n" +
						"	<tr><td>Identity:</td><td><input type='text' size='30' name='openid_identifier'/></td></tr>\n" +
						"	<tr><td colspan='2'><input name=\"submit\" type=\"submit\" value=\"Login\"/></td></tr>\n" +
						"</table>\n" +
						"</form></body></html>";

		this.mvc.perform(get("/login")).andExpect(content().string(expectedContent));
	}

	@Test
	public void failedLoginWhenConfiguredWithCustomAuthenticationFailureThenForwardsAccordingly()
		throws Exception {

		this.spring.configLocations(this.xml("WithAuthenticationFailureForwardUrl")).autowire();

		this.mvc.perform(post("/login")
							.param("username", "bob")
							.param("password", "invalidpassword"))
				.andExpect(status().isOk())
				.andExpect(forwardedUrl("/failure_forward_url"))
				.andExpect(request().attribute(WebAttributes.AUTHENTICATION_EXCEPTION, not(nullValue())));
	}

	@Test
	public void successfulLoginWhenConfiguredWithCustomAuthenticationSuccessThenForwardsAccordingly()
		throws Exception {

		this.spring.configLocations(this.xml("WithAuthenticationSuccessForwardUrl")).autowire();

		this.mvc.perform(post("/login")
				.param("username", "user")
				.param("password", "password"))
				.andExpect(status().isOk())
				.andExpect(forwardedUrl("/success_forward_url"));
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}
}
