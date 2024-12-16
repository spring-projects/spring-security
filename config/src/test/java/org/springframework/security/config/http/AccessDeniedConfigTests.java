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

package org.springframework.security.config.http;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Luke Taylor
 * @author Josh Cummings
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class AccessDeniedConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/AccessDeniedConfigTests";

	@Autowired
	MockMvc mvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void configureWhenAccessDeniedHandlerIsMissingLeadingSlashThenException() {
		SpringTestContext context = this.spring.configLocations(this.xml("NoLeadingSlash"));
		/*
		 * NOTE: Original error message "errorPage must begin with '/'" no longer shows up
		 * in stack trace as of Spring Framework 6.x.
		 *
		 * See https://github.com/spring-projects/spring-framework/issues/25162.
		 */
		assertThatExceptionOfType(BeanCreationException.class).isThrownBy(() -> context.autowire())
			.havingRootCause()
			.withMessageContaining("Property 'errorPage' threw exception");
	}

	@Test
	@WithMockUser
	public void configureWhenAccessDeniedHandlerRefThenAutowire() throws Exception {
		this.spring.configLocations(this.xml("AccessDeniedHandler")).autowire();
		this.mvc.perform(get("/")).andExpect(status().is(HttpStatus.GONE.value()));
	}

	@Test
	public void configureWhenAccessDeniedHandlerUsesPathAndRefThenException() {
		SpringTestContext context = this.spring.configLocations(this.xml("UsesPathAndRef"));
		assertThatExceptionOfType(BeanDefinitionParsingException.class).isThrownBy(() -> context.autowire())
			.withMessageContaining("attribute error-page cannot be used together with the 'ref' attribute");
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	public static class GoneAccessDeniedHandler implements AccessDeniedHandler {

		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response,
				AccessDeniedException accessDeniedException) {
			response.setStatus(HttpStatus.GONE.value());
		}

	}

}
