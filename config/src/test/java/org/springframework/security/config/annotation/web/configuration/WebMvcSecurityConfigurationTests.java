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

package org.springframework.security.config.annotation.web.configuration;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * @author Rob Winch
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration
@WebAppConfiguration
public class WebMvcSecurityConfigurationTests {

	@Autowired
	WebApplicationContext context;

	MockMvc mockMvc;

	Authentication authentication;

	@BeforeEach
	public void setup() {
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.context).build();
		this.authentication = new TestingAuthenticationToken("user", "password",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void authenticationPrincipalResolved() throws Exception {
		this.mockMvc.perform(get("/authentication-principal"))
			.andExpect(assertResult(this.authentication.getPrincipal()))
			.andExpect(view().name("authentication-principal-view"));
	}

	@Test
	public void deprecatedAuthenticationPrincipalResolved() throws Exception {
		this.mockMvc.perform(get("/deprecated-authentication-principal"))
			.andExpect(assertResult(this.authentication.getPrincipal()))
			.andExpect(view().name("deprecated-authentication-principal-view"));
	}

	@Test
	public void csrfToken() throws Exception {
		CsrfToken csrfToken = new DefaultCsrfToken("headerName", "paramName", "token");
		MockHttpServletRequestBuilder request = get("/csrf").requestAttr(CsrfToken.class.getName(), csrfToken);
		this.mockMvc.perform(request).andExpect(assertResult(csrfToken));
	}

	@Test
	public void metaAnnotationWhenTemplateDefaultsBeanThenResolvesExpression() throws Exception {
		this.mockMvc.perform(get("/hi")).andExpect(content().string("Hi, Stranger!"));
		Authentication harold = new TestingAuthenticationToken("harold", "password",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		SecurityContextHolder.getContext().setAuthentication(harold);
		this.mockMvc.perform(get("/hi")).andExpect(content().string("Hi, Harold!"));
	}

	@Test
	public void resolveMetaAnnotationWhenTemplateDefaultsBeanThenResolvesExpression() throws Exception {
		this.mockMvc.perform(get("/hello")).andExpect(content().string("user"));
		Authentication harold = new TestingAuthenticationToken("harold", "password",
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		SecurityContextHolder.getContext().setAuthentication(harold);
		this.mockMvc.perform(get("/hello")).andExpect(content().string("harold"));
	}

	private ResultMatcher assertResult(Object expected) {
		return model().attribute("result", expected);
	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target(ElementType.PARAMETER)
	@AuthenticationPrincipal(expression = "#this.equals('{value}')")
	@interface IsUser {

		String value() default "user";

	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@CurrentSecurityContext(expression = "authentication.{property}")
	@interface CurrentAuthenticationProperty {

		String property();

	}

	@Controller
	static class TestController {

		@RequestMapping("/authentication-principal")
		ModelAndView authenticationPrincipal(@AuthenticationPrincipal String principal) {
			return new ModelAndView("authentication-principal-view", "result", principal);
		}

		@RequestMapping("/deprecated-authentication-principal")
		ModelAndView deprecatedAuthenticationPrincipal(
				@org.springframework.security.web.bind.annotation.AuthenticationPrincipal String principal) {
			return new ModelAndView("deprecated-authentication-principal-view", "result", principal);
		}

		@RequestMapping("/csrf")
		ModelAndView csrf(CsrfToken token) {
			return new ModelAndView("view", "result", token);
		}

		@GetMapping("/hi")
		@ResponseBody
		String ifUser(@IsUser("harold") boolean isHarold) {
			if (isHarold) {
				return "Hi, Harold!";
			}
			else {
				return "Hi, Stranger!";
			}
		}

		@GetMapping("/hello")
		@ResponseBody
		String getCurrentAuthenticationProperty(
				@CurrentAuthenticationProperty(property = "principal") String principal) {
			return principal;
		}

	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class Config {

		@Bean
		TestController testController() {
			return new TestController();
		}

		@Bean
		AnnotationTemplateExpressionDefaults templateExpressionDefaults() {
			return new AnnotationTemplateExpressionDefaults();
		}

	}

}
