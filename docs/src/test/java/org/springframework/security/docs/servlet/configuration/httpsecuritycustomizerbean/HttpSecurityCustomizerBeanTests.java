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

package org.springframework.security.docs.servlet.configuration.httpsecuritycustomizerbean;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ThrowingCustomizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/**
 *
 */
@ExtendWith(SpringTestContextExtension.class)
public class HttpSecurityCustomizerBeanTests {
	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test
	void httpSecurityCustomizer() throws Exception {
		this.spring.register(HttpSecurityCustomizerBeanConfiguration.class).autowire();
		// @formatter:off
		this.mockMvc
			.perform(get("/"))
			.andExpect(redirectsToHttps());
		// headers are not sent back as a part of the redirect to https, so a separate request is necessary
		this.mockMvc.perform(get("https://localhost/"))
			.andExpect(cspIsObjectSrcNone());
		// @formatter:on
	}

	private static @NotNull ResultMatcher redirectsToHttps() {
		return mvcResult -> assertThat(
			mvcResult.getResponse().getRedirectedUrl()).startsWith("https://");
	}

	private static @NotNull ResultMatcher cspIsObjectSrcNone() {
		return header().string("Content-Security-Policy", "object-src 'none'");
	}

}
