/*
 * Copyright 2002-2023 the original author or authors.
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

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.stereotype.Component;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector.CachedResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * @author Rob Winch
 */
@ContextConfiguration
@WebAppConfiguration
@ExtendWith({ SpringExtension.class })
@SecurityTestExecutionListeners
class HandlerMappingIntrospectorCacheFilterConfigTests {

	@Autowired
	WebApplicationContext context;

	MockMvc mockMvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	MvcEnabledConfig.CaptureHandlerMappingIntrospectorCache captureCacheFilter;

	@Autowired(required = false)
	HandlerMappingIntrospector hmi;

	@Test
	@WithMockUser
	void hmiIsCached() throws Exception {
		this.spring.register(MvcEnabledConfig.class).autowire();
		this.mockMvc = MockMvcBuilders.webAppContextSetup(this.context)
			.apply(springSecurity())
			.addFilter(this.captureCacheFilter)
			.build();
		this.mockMvc.perform(get("/"));
		assertThat(this.captureCacheFilter.cachedResult).isNotNull();
	}

	@Test
	@WithMockUser
	void configurationLoadsIfNoHMI() {
		// no BeanCreationException due to missing HandlerMappingIntrospector
		this.spring.register(MvcNotEnabledConfig.class).autowire();
		// ensure assumption of HandlerMappingIntrospector is null is true
		assertThat(this.hmi).isNull();
	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class MvcEnabledConfig {

		@Component
		static class CaptureHandlerMappingIntrospectorCache implements Filter {

			final HandlerMappingIntrospector hmi;

			private CachedResult cachedResult;

			CaptureHandlerMappingIntrospectorCache(HandlerMappingIntrospector hmi) {
				this.hmi = hmi;
			}

			@Override
			public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
					throws IOException, ServletException {
				// capture the old cached value to check that caching has already occurred
				this.cachedResult = this.hmi.setCache((HttpServletRequest) request);
				chain.doFilter(request, response);
			}

		}

	}

	@Configuration
	@EnableWebSecurity
	static class MvcNotEnabledConfig {

	}

}
