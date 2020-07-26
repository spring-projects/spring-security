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

import java.util.Arrays;
import java.util.Collections;

import com.google.common.net.HttpHeaders;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link CorsConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
public class CorsConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenNoMvcThenException() {
		assertThatThrownBy(() -> this.spring.register(DefaultCorsConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class).hasMessageContaining(
						"Please ensure Spring Security & Spring MVC are configured in a shared ApplicationContext");
	}

	@Test
	public void getWhenCrossOriginAnnotationThenRespondsWithCorsHeaders() throws Exception {
		this.spring.register(MvcCorsConfig.class).autowire();

		this.mvc.perform(get("/").header(HttpHeaders.ORIGIN, "https://example.com"))
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@Test
	public void optionsWhenCrossOriginAnnotationThenRespondsWithCorsHeaders() throws Exception {
		this.spring.register(MvcCorsConfig.class).autowire();

		this.mvc.perform(options("/")
				.header(org.springframework.http.HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
				.header(HttpHeaders.ORIGIN, "https://example.com")).andExpect(status().isOk())
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@Test
	public void getWhenDefaultsInLambdaAndCrossOriginAnnotationThenRespondsWithCorsHeaders() throws Exception {
		this.spring.register(MvcCorsInLambdaConfig.class).autowire();

		this.mvc.perform(get("/").header(HttpHeaders.ORIGIN, "https://example.com"))
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@Test
	public void optionsWhenDefaultsInLambdaAndCrossOriginAnnotationThenRespondsWithCorsHeaders() throws Exception {
		this.spring.register(MvcCorsInLambdaConfig.class).autowire();

		this.mvc.perform(options("/")
				.header(org.springframework.http.HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
				.header(HttpHeaders.ORIGIN, "https://example.com")).andExpect(status().isOk())
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@Test
	public void getWhenCorsConfigurationSourceBeanThenRespondsWithCorsHeaders() throws Exception {
		this.spring.register(ConfigSourceConfig.class).autowire();

		this.mvc.perform(get("/").header(HttpHeaders.ORIGIN, "https://example.com"))
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@Test
	public void optionsWhenCorsConfigurationSourceBeanThenRespondsWithCorsHeaders() throws Exception {
		this.spring.register(ConfigSourceConfig.class).autowire();

		this.mvc.perform(options("/")
				.header(org.springframework.http.HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
				.header(HttpHeaders.ORIGIN, "https://example.com")).andExpect(status().isOk())
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@Test
	public void getWhenMvcCorsInLambdaConfigAndCorsConfigurationSourceBeanThenRespondsWithCorsHeaders()
			throws Exception {
		this.spring.register(ConfigSourceInLambdaConfig.class).autowire();

		this.mvc.perform(get("/").header(HttpHeaders.ORIGIN, "https://example.com"))
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@Test
	public void optionsWhenMvcCorsInLambdaConfigAndCorsConfigurationSourceBeanThenRespondsWithCorsHeaders()
			throws Exception {
		this.spring.register(ConfigSourceInLambdaConfig.class).autowire();

		this.mvc.perform(options("/")
				.header(org.springframework.http.HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
				.header(HttpHeaders.ORIGIN, "https://example.com")).andExpect(status().isOk())
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@Test
	public void getWhenCorsFilterBeanThenRespondsWithCorsHeaders() throws Exception {
		this.spring.register(CorsFilterConfig.class).autowire();

		this.mvc.perform(get("/").header(HttpHeaders.ORIGIN, "https://example.com"))
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@Test
	public void optionsWhenCorsFilterBeanThenRespondsWithCorsHeaders() throws Exception {
		this.spring.register(CorsFilterConfig.class).autowire();

		this.mvc.perform(options("/")
				.header(org.springframework.http.HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
				.header(HttpHeaders.ORIGIN, "https://example.com")).andExpect(status().isOk())
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@Test
	public void getWhenConfigSourceInLambdaConfigAndCorsFilterBeanThenRespondsWithCorsHeaders() throws Exception {
		this.spring.register(CorsFilterInLambdaConfig.class).autowire();

		this.mvc.perform(get("/").header(HttpHeaders.ORIGIN, "https://example.com"))
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@Test
	public void optionsWhenConfigSourceInLambdaConfigAndCorsFilterBeanThenRespondsWithCorsHeaders() throws Exception {
		this.spring.register(CorsFilterInLambdaConfig.class).autowire();

		this.mvc.perform(options("/")
				.header(org.springframework.http.HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name())
				.header(HttpHeaders.ORIGIN, "https://example.com")).andExpect(status().isOk())
				.andExpect(header().exists("Access-Control-Allow-Origin"))
				.andExpect(header().exists("X-Content-Type-Options"));
	}

	@EnableWebSecurity
	static class DefaultCorsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.cors();
			// @formatter:on
		}

	}

	@EnableWebMvc
	@EnableWebSecurity
	static class MvcCorsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.cors();
			// @formatter:on
		}

		@RestController
		@CrossOrigin(methods = { RequestMethod.GET, RequestMethod.POST })
		static class CorsController {

			@RequestMapping("/")
			String hello() {
				return "Hello";
			}

		}

	}

	@EnableWebMvc
	@EnableWebSecurity
	static class MvcCorsInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.cors(withDefaults());
			// @formatter:on
		}

		@RestController
		@CrossOrigin(methods = { RequestMethod.GET, RequestMethod.POST })
		static class CorsController {

			@RequestMapping("/")
			String hello() {
				return "Hello";
			}

		}

	}

	@EnableWebSecurity
	static class ConfigSourceConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.cors();
			// @formatter:on
		}

		@Bean
		CorsConfigurationSource corsConfigurationSource() {
			UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
			CorsConfiguration corsConfiguration = new CorsConfiguration();
			corsConfiguration.setAllowedOrigins(Collections.singletonList("*"));
			corsConfiguration.setAllowedMethods(Arrays.asList(RequestMethod.GET.name(), RequestMethod.POST.name()));
			source.registerCorsConfiguration("/**", corsConfiguration);
			return source;
		}

	}

	@EnableWebSecurity
	static class ConfigSourceInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.cors(withDefaults());
			// @formatter:on
		}

		@Bean
		CorsConfigurationSource corsConfigurationSource() {
			UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
			CorsConfiguration corsConfiguration = new CorsConfiguration();
			corsConfiguration.setAllowedOrigins(Collections.singletonList("*"));
			corsConfiguration.setAllowedMethods(Arrays.asList(RequestMethod.GET.name(), RequestMethod.POST.name()));
			source.registerCorsConfiguration("/**", corsConfiguration);
			return source;
		}

	}

	@EnableWebSecurity
	static class CorsFilterConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.cors();
			// @formatter:on
		}

		@Bean
		CorsFilter corsFilter() {
			UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
			CorsConfiguration corsConfiguration = new CorsConfiguration();
			corsConfiguration.setAllowedOrigins(Collections.singletonList("*"));
			corsConfiguration.setAllowedMethods(Arrays.asList(RequestMethod.GET.name(), RequestMethod.POST.name()));
			source.registerCorsConfiguration("/**", corsConfiguration);
			return new CorsFilter(source);
		}

	}

	@EnableWebSecurity
	static class CorsFilterInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.cors(withDefaults());
			// @formatter:on
		}

		@Bean
		CorsFilter corsFilter() {
			UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
			CorsConfiguration corsConfiguration = new CorsConfiguration();
			corsConfiguration.setAllowedOrigins(Collections.singletonList("*"));
			corsConfiguration.setAllowedMethods(Arrays.asList(RequestMethod.GET.name(), RequestMethod.POST.name()));
			source.registerCorsConfiguration("/**", corsConfiguration);
			return new CorsFilter(source);
		}

	}

}
