/*
 * Copyright 2002-2016 the original author or authors.
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.servlet.Filter;

import org.junit.After;
import org.junit.Test;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.XmlWebApplicationContext;

public class HttpInterceptUrlTests {
	ConfigurableWebApplicationContext context;

	MockMvc mockMvc;

	@After
	public void close() {
		if(context != null) {
			context.close();
		}
	}

	@Test
	public void interceptUrlWhenRequestMatcherRefThenWorks() throws Exception {
		loadConfig("interceptUrlWhenRequestMatcherRefThenWorks.xml");

		mockMvc.perform(get("/foo"))
			.andExpect(status().isUnauthorized());

		mockMvc.perform(get("/FOO"))
			.andExpect(status().isUnauthorized());

		mockMvc.perform(get("/other"))
			.andExpect(status().isOk());
	}

	private void loadConfig(String... configLocations) {
		for(int i=0;i<configLocations.length;i++) {
			configLocations[i] = getClass().getName().replaceAll("\\.", "/") + "-" + configLocations[i];
		}
		XmlWebApplicationContext context = new XmlWebApplicationContext();
		context.setConfigLocations(configLocations);
		context.setServletContext(new MockServletContext());
		context.refresh();
		this.context = context;

		context.getAutowireCapableBeanFactory().autowireBean(this);

		Filter springSecurityFilterChain = context.getBean("springSecurityFilterChain", Filter.class);
		mockMvc = MockMvcBuilders
				.standaloneSetup(new FooController())
				.addFilters(springSecurityFilterChain)
				.build();
	}

	@RestController
	static class FooController {
		@GetMapping("/*")
		String foo() {
			return "foo";
		}
	}
}
