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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/**
 * Tests for {@link HeadersConfigurer}.
 *
 * @author Ankur Pathak
 */
@ExtendWith(SpringTestContextExtension.class)
public class HeadersConfigurerEagerHeadersTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void requestWhenHeadersEagerlyConfiguredThenHeadersAreWritten() throws Exception {
		this.spring.register(HeadersAtTheBeginningOfRequestConfig.class).autowire();
		this.mvc.perform(get("/").secure(true)).andExpect(header().string("X-Content-Type-Options", "nosniff"))
				.andExpect(header().string("X-Frame-Options", "DENY"))
				.andExpect(header().string("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains"))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(HttpHeaders.EXPIRES, "0"))
				.andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
				.andExpect(header().string("X-XSS-Protection", "0"));
	}

	@Configuration
	@EnableWebSecurity
	public static class HeadersAtTheBeginningOfRequestConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.headers()
					.addObjectPostProcessor(new ObjectPostProcessor<HeaderWriterFilter>() {
						@Override
						public HeaderWriterFilter postProcess(HeaderWriterFilter filter) {
							filter.setShouldWriteHeadersEagerly(true);
							return filter;
						}
					});
			return http.build();
			// @formatter:on
		}

	}

}
