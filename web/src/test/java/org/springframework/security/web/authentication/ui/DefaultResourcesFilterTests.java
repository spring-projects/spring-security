/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.authentication.ui;

import org.junit.jupiter.api.Test;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Daniel Garnier-Moiroux
 * @since 6.4
 */
public class DefaultResourcesFilterTests {

	private final DefaultResourcesFilter filter = DefaultResourcesFilter.css();

	private final MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new Object()).addFilters(this.filter).build();

	@Test
	public void doFilterThenRender() throws Exception {
		this.mockMvc.perform(get("/default-ui.css"))
			.andExpect(status().isOk())
			.andExpect(content().contentType("text/css;charset=UTF-8"))
			.andExpect(content().string(containsString("body {")));
	}

	@Test
	public void doFilterWhenPathDoesNotMatchThenCallsThrough() throws Exception {
		this.mockMvc.perform(get("/does-not-match")).andExpect(status().isNotFound());
	}

	@Test
	void toStringPrintsPathAndResource() {
		assertThat(this.filter.toString()).isEqualTo(
				"DefaultResourcesFilter [matcher=Ant [pattern='/default-ui.css', GET], resource=org/springframework/security/default-ui.css]");
	}

}
