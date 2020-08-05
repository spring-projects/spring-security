/*
 * Copyright 2002-2017 the original author or authors.
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

import java.lang.reflect.Method;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 */
public class NamespaceHttpBasicTests {

	@Mock
	Method method;

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	MockFilterChain chain;

	ConfigurableApplicationContext context;

	Filter springSecurityFilterChain;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest("GET", "");
		this.request.setMethod("GET");
		this.response = new MockHttpServletResponse();
		this.chain = new MockFilterChain();
	}

	@After
	public void teardown() {
		if (this.context != null) {
			this.context.close();
		}
	}

	// gh-3296
	@Test
	public void httpBasicWithPasswordEncoder() throws Exception {
		// @formatter:off
		loadContext("<http>\n" +
			"		<intercept-url pattern=\"/**\" access=\"hasRole('USER')\" />\n" +
			"		<http-basic />\n" +
			"	</http>\n" +
			"\n" +
			"	<authentication-manager id=\"authenticationManager\">\n" +
			"		<authentication-provider>\n" +
			"			<password-encoder ref=\"passwordEncoder\" />\n" +
			"			<user-service>\n" +
			"				<user name=\"user\" password=\"$2a$10$Zk1MxFEt7YYji4Ccy9xlfuewWzUMsmHZfy4UcCmNKVV6z5i/JNGJW\" authorities=\"ROLE_USER\"/>\n" +
			"			</user-service>\n" +
			"		</authentication-provider>\n" +
			"	</authentication-manager>\n" +
			"	<b:bean id=\"passwordEncoder\"\n" +
			"		class=\"org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder\" />");
			// @formatter:on

		this.request.addHeader("Authorization",
				"Basic " + Base64.getEncoder().encodeToString("user:test".getBytes("UTF-8")));

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
	}

	// gh-4220
	@Test
	public void httpBasicUnauthorizedOnDefault() throws Exception {
		// @formatter:off
		loadContext("<http>\n" +
			"		<intercept-url pattern=\"/**\" access=\"hasRole('USER')\" />\n" +
			"		<http-basic />\n" +
			"	</http>\n" +
			"\n" +
			"	<authentication-manager />");
		// @formatter:on

		this.springSecurityFilterChain.doFilter(this.request, this.response, this.chain);

		assertThat(this.response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		assertThat(this.response.getHeader("WWW-Authenticate")).isEqualTo("Basic realm=\"Realm\"");
	}

	private void loadContext(String context) {
		this.context = new InMemoryXmlApplicationContext(context);
		this.springSecurityFilterChain = this.context.getBean("springSecurityFilterChain", Filter.class);
	}

}
