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

import java.util.Collections;

import org.junit.jupiter.api.Test;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class DefaultLogoutPageGeneratingFilterTests {

	private DefaultLogoutPageGeneratingFilter filter = new DefaultLogoutPageGeneratingFilter();

	@Test
	public void doFilterWhenNoHiddenInputsThenPageRendered() throws Exception {
		MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new Object()).addFilter(this.filter).build();
		mockMvc.perform(get("/logout"))
			.andExpect(content().string(containsString("Are you sure you want to log out?")))
			.andExpect(content().contentType("text/html;charset=UTF-8"));
	}

	@Test
	public void doFilterWhenHiddenInputsSetThenHiddenInputsRendered() throws Exception {
		this.filter.setResolveHiddenInputs((r) -> Collections.singletonMap("_csrf", "csrf-token-1"));
		MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new Object()).addFilters(this.filter).build();
		mockMvc.perform(get("/logout"))
			.andExpect(content()
				.string(containsString("<input name=\"_csrf\" type=\"hidden\" value=\"csrf-token-1\" />")));
	}

	@Test
	public void doFilterWhenRequestContextThenActionContainsRequestContext() throws Exception {
		MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new Object()).addFilters(this.filter).build();
		mockMvc.perform(get("/context/logout").contextPath("/context"))
			.andExpect(content().string(containsString("action=\"/context/logout\"")));
	}

}
