/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.docs.servlet.integrations.corspreflightrequesthandler;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.PreFlightRequestHandler;

@Configuration
@EnableWebSecurity
class CorsPreFlightRequestHandlerExample {

	@Bean
	PreFlightRequestHandler preFlightRequestHandler() {
		return (request, response) -> {
			// custom preflight handling (for example, write CORS headers or complete the response)
		};
	}

	@Bean
	SecurityFilterChain springSecurity(HttpSecurity http, PreFlightRequestHandler preFlightRequestHandler) {
		// tag::preflightRequestHandler[]
		http
			// ..
			.cors((cors) -> cors
				.preFlightRequestHandler(preFlightRequestHandler)
			);
		return http.build();
		// end::preflightRequestHandler[]
	}

}
