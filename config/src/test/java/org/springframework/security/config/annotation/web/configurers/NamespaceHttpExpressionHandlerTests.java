/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers;


import java.security.Principal;

import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

/**
 * Tests to verify that all the functionality of <expression-handler> attributes is present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SecurityTestExecutionListeners
public class NamespaceHttpExpressionHandlerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	@WithMockUser
	public void getWhenHasCustomExpressionHandlerThenMatchesNamespace() throws Exception {
		this.spring.register(ExpressionHandlerController.class, ExpressionHandlerConfig.class).autowire();
		this.mvc.perform(get("/whoami")).andExpect(content().string("user"));
		verifyBean("expressionParser", ExpressionParser.class).parseExpression("hasRole('USER')");
	}

	@EnableWebMvc
	@EnableWebSecurity
	private static class ExpressionHandlerConfig extends WebSecurityConfigurerAdapter {
		ExpressionHandlerConfig() {}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser("rod").password("password").roles("USER", "ADMIN");
			// @formatter:on
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
			handler.setExpressionParser(expressionParser());
			// @formatter:off
			http
				.authorizeRequests()
					.expressionHandler(handler)
					.anyRequest().access("hasRole('USER')");
			// @formatter:on
		}

		@Bean
		ExpressionParser expressionParser() {
			return spy(new SpelExpressionParser());
		}
	}

	@RestController
	private static class ExpressionHandlerController {
		@GetMapping("/whoami")
		String whoami(Principal user) {
			return user.getName();
		}
	}

	private <T> T verifyBean(String beanName, Class<T> beanClass) {
		return verify(this.spring.getContext().getBean(beanName, beanClass));
	}
}
