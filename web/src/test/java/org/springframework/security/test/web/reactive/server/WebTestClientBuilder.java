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
package org.springframework.security.test.web.reactive.server;

import org.springframework.http.HttpStatus;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient.Builder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.WebFilter;

/**
 * Provides a convenient mechanism for running {@link WebTestClient} against
 * {@link WebFilter}
 *
 * @author Rob Winch
 * @since 5.0
 *
 */
public class WebTestClientBuilder {

	public static Builder bindToWebFilters(WebFilter... webFilters) {
		return WebTestClient.bindToController(new Http200RestController()).webFilter(webFilters).configureClient();
	}

	public static Builder bindToWebFilters(SecurityWebFilterChain securityWebFilterChain) {
		return bindToWebFilters(new WebFilterChainProxy(securityWebFilterChain));
	}

	public static Builder bindToControllerAndWebFilters(Class<?> controller, WebFilter... webFilters) {
		return WebTestClient.bindToController(controller).webFilter(webFilters).configureClient();
	}

	public static Builder bindToControllerAndWebFilters(Class<?> controller, SecurityWebFilterChain securityWebFilterChain) {
		return bindToControllerAndWebFilters(controller, new WebFilterChainProxy(securityWebFilterChain));
	}

	@RestController
	public static class Http200RestController {
		@RequestMapping("/**")
		@ResponseStatus(HttpStatus.OK)
		public String ok() {
			return "ok";
		}
	}

}
