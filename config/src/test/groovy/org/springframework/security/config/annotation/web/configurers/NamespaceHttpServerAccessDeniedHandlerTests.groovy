/*
 * Copyright 2002-2013 the original author or authors.
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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.BaseSpringSpec;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.BaseWebConfig;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.ExceptionTranslationFilter;

/**
 * Tests to verify that all the functionality of <access-denied-handler> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpServerAccessDeniedHandlerTests extends BaseSpringSpec {
	def "http/access-denied-handler@error-page"() {
		when:
		loadConfig(AccessDeniedPageConfig)
		then:
		findFilter(ExceptionTranslationFilter).accessDeniedHandler.errorPage == "/AccessDeniedPageConfig"
	}

	@Configuration
	static class AccessDeniedPageConfig extends BaseWebConfig {
		protected void configure(HttpSecurity http) {
			http.
				exceptionHandling()
					.accessDeniedPage("/AccessDeniedPageConfig")
		}
	}

	def "http/access-denied-handler@ref"() {
		when:
		loadConfig(AccessDeniedHandlerRefConfig)
		then:
		findFilter(ExceptionTranslationFilter).accessDeniedHandler.class == AccessDeniedHandlerRefConfig.CustomAccessDeniedHandler
	}

	@Configuration
	static class AccessDeniedHandlerRefConfig extends BaseWebConfig {
		protected void configure(HttpSecurity http) {
			CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler()
			http.
				exceptionHandling()
					.accessDeniedHandler(accessDeniedHandler)
		}

		static class CustomAccessDeniedHandler implements AccessDeniedHandler {
			public void handle(HttpServletRequest request,
					HttpServletResponse response,
					AccessDeniedException accessDeniedException)
					throws IOException, ServletException {
			}
		}
	}
}
