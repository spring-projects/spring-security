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

package org.springframework.security.web.authentication.ui;

import java.util.Collections;

import org.junit.Test;

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

		mockMvc.perform(get("/logout")).andExpect(content().string("<!DOCTYPE html>\n" + "<html lang=\"en\">\n"
				+ "  <head>\n" + "    <meta charset=\"utf-8\">\n"
				+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
				+ "    <meta name=\"description\" content=\"\">\n" + "    <meta name=\"author\" content=\"\">\n"
				+ "    <title>Confirm Log Out?</title>\n"
				+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
				+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
				+ "  </head>\n" + "  <body>\n" + "     <div class=\"container\">\n"
				+ "      <form class=\"form-signin\" method=\"post\" action=\"/logout\">\n"
				+ "        <h2 class=\"form-signin-heading\">Are you sure you want to log out?</h2>\n"
				+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Log Out</button>\n"
				+ "      </form>\n" + "    </div>\n" + "  </body>\n" + "</html>"))
				.andExpect(content().contentType("text/html;charset=UTF-8"));
	}

	@Test
	public void doFilterWhenHiddenInputsSetThenHiddenInputsRendered() throws Exception {
		this.filter.setResolveHiddenInputs(r -> Collections.singletonMap("_csrf", "csrf-token-1"));
		MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new Object()).addFilters(this.filter).build();

		mockMvc.perform(get("/logout")).andExpect(
				content().string(containsString("<input name=\"_csrf\" type=\"hidden\" value=\"csrf-token-1\" />")));
	}

	@Test
	public void doFilterWhenRequestContextThenActionContainsRequestContext() throws Exception {
		MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new Object()).addFilters(this.filter).build();

		mockMvc.perform(get("/context/logout").contextPath("/context"))
				.andExpect(content().string(containsString("action=\"/context/logout\"")));
	}

}
