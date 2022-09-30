/*
 * Copyright 2002-2022 the original author or authors.
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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

/**
 * Tests to verify that all the functionality of &lt;expression-handler&gt; attributes is
 * present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class NamespaceHttpExpressionHandlerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	@WithMockUser
	public void getWhenHasCustomExpressionHandlerThenMatchesNamespace() throws Exception {
		this.spring.register(ExpressionHandlerController.class, ExpressionHandlerConfig.class).autowire();
		this.mvc.perform(get("/whoami")).andExpect(content().string("user"));
		verifyBean("expressionParser", ExpressionParser.class).parseExpression("hasRole('USER')");
	}

	private <T> T verifyBean(String beanName, Class<T> beanClass) {
		return verify(this.spring.getContext().getBean(beanName, beanClass));
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class ExpressionHandlerConfig {

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("rod").password("password")
					.roles("USER", "ADMIN").build();
			return new InMemoryUserDetailsManager(user);
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
			handler.setExpressionParser(expressionParser());
			// @formatter:off
			http
				.authorizeRequests()
					.expressionHandler(handler)
					.anyRequest().access("hasRole('USER')");
			// @formatter:on
			return http.build();
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

}
