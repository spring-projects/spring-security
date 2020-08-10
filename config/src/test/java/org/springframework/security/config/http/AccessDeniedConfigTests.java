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

import org.eclipse.jetty.http.HttpStatus;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Luke Taylor
 * @author Josh Cummings
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SecurityTestExecutionListeners
public class AccessDeniedConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/AccessDeniedConfigTests";

	@Autowired
	MockMvc mvc;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	public void configureWhenAccessDeniedHandlerIsMissingLeadingSlashThenException() {
		SpringTestContext context = this.spring.configLocations(this.xml("NoLeadingSlash"));

		assertThatThrownBy(() -> context.autowire()).isInstanceOf(BeanCreationException.class)
				.hasMessageContaining("errorPage must begin with '/'");
	}

	@Test
	@WithMockUser
	public void configureWhenAccessDeniedHandlerRefThenAutowire() throws Exception {

		this.spring.configLocations(this.xml("AccessDeniedHandler")).autowire();

		this.mvc.perform(get("/")).andExpect(status().is(HttpStatus.GONE_410));
	}

	@Test
	public void configureWhenAccessDeniedHandlerUsesPathAndRefThenException() {
		SpringTestContext context = this.spring.configLocations(this.xml("UsesPathAndRef"));

		assertThatThrownBy(() -> context.autowire()).isInstanceOf(BeanDefinitionParsingException.class)
				.hasMessageContaining("attribute error-page cannot be used together with the 'ref' attribute");
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	public static class GoneAccessDeniedHandler implements AccessDeniedHandler {

		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response,
				AccessDeniedException accessDeniedException) {

			response.setStatus(HttpStatus.GONE_410);
		}

	}

}
