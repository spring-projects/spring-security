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

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.http.HttpHeaders.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/**
 * Tests for {@link HeadersConfigurer}.
 *
 * @author Ankur Pathak
 */
public class HeadersConfigurerEagerHeadersTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@EnableWebSecurity
	public static class HeadersAtTheBeginningOfRequestConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @ formatter:off
			http.headers().addObjectPostProcessor(new ObjectPostProcessor<HeaderWriterFilter>() {
				@Override
				public HeaderWriterFilter postProcess(HeaderWriterFilter filter) {
					filter.setShouldWriteHeadersEagerly(true);
					return filter;
				}
			});
			// @ formatter:on
		}

	}

	@Test
	public void requestWhenHeadersEagerlyConfiguredThenHeadersAreWritten() throws Exception {
		this.spring.register(HeadersAtTheBeginningOfRequestConfig.class).autowire();

		this.mvc.perform(get("/").secure(true)).andExpect(header().string("X-Content-Type-Options", "nosniff"))
				.andExpect(header().string("X-Frame-Options", "DENY"))
				.andExpect(header().string("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains"))
				.andExpect(header().string(CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(EXPIRES, "0")).andExpect(header().string(PRAGMA, "no-cache"))
				.andExpect(header().string("X-XSS-Protection", "1; mode=block"));
	}

}
