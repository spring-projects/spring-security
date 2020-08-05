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
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Tim Ysewyn
 * @author Josh Cummings
 */
public class HttpCorsConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/HttpCorsConfigTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void autowireWhenMissingMvcThenGivesInformativeError() {
		assertThatThrownBy(() -> this.spring.configLocations(this.xml("RequiresMvc")).autowire())
				.isInstanceOf(BeanCreationException.class).hasMessageContaining(
						"Please ensure Spring Security & Spring MVC are configured in a shared ApplicationContext");
	}

	@Test
	public void getWhenUsingCorsThenDoesSpringSecurityCorsHandshake() throws Exception {

		this.spring.configLocations(this.xml("WithCors")).autowire();

		this.mvc.perform(get("/").with(this.approved())).andExpect(corsResponseHeaders())
				.andExpect((status().isIAmATeapot()));

		this.mvc.perform(options("/").with(this.preflight())).andExpect(corsResponseHeaders())
				.andExpect(status().isOk());
	}

	@Test
	public void getWhenUsingCustomCorsConfigurationSourceThenDoesSpringSecurityCorsHandshake() throws Exception {

		this.spring.configLocations(this.xml("WithCorsConfigurationSource")).autowire();

		this.mvc.perform(get("/").with(this.approved())).andExpect(corsResponseHeaders())
				.andExpect((status().isIAmATeapot()));

		this.mvc.perform(options("/").with(this.preflight())).andExpect(corsResponseHeaders())
				.andExpect(status().isOk());
	}

	@Test
	public void getWhenUsingCustomCorsFilterThenDoesSPringSecurityCorsHandshake() throws Exception {

		this.spring.configLocations(this.xml("WithCorsFilter")).autowire();

		this.mvc.perform(get("/").with(this.approved())).andExpect(corsResponseHeaders())
				.andExpect((status().isIAmATeapot()));

		this.mvc.perform(options("/").with(this.preflight())).andExpect(corsResponseHeaders())
				.andExpect(status().isOk());
	}

	@RestController
	@CrossOrigin(methods = { RequestMethod.GET, RequestMethod.POST })
	static class CorsController {

		@RequestMapping("/")
		String hello() {
			return "Hello";
		}

	}

	static class MyCorsConfigurationSource extends UrlBasedCorsConfigurationSource {

		MyCorsConfigurationSource() {
			CorsConfiguration configuration = new CorsConfiguration();
			configuration.setAllowedOrigins(Arrays.asList("*"));
			configuration.setAllowedMethods(Arrays.asList(RequestMethod.GET.name(), RequestMethod.POST.name()));

			super.registerCorsConfiguration("/**", configuration);
		}

	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	private RequestPostProcessor preflight() {
		return cors(true);
	}

	private RequestPostProcessor approved() {
		return cors(false);
	}

	private RequestPostProcessor cors(boolean preflight) {
		return (request) -> {
			request.addHeader(HttpHeaders.ORIGIN, "https://example.com");

			if (preflight) {
				request.setMethod(HttpMethod.OPTIONS.name());
				request.addHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, HttpMethod.POST.name());
			}

			return request;
		};
	}

	private ResultMatcher corsResponseHeaders() {
		return result -> {
			header().exists("Access-Control-Allow-Origin").match(result);
			header().exists("X-Content-Type-Options").match(result);
		};
	}

}
