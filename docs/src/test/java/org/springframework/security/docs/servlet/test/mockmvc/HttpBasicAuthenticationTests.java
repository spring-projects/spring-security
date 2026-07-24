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

package org.springframework.security.docs.servlet.test.mockmvc;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

class HttpBasicAuthenticationTests {

	@Test
	void basicAuthentication() throws Exception {
		MockMvc mvc = MockMvcBuilders.standaloneSetup(new TestController()).build();

		MvcResult result =
				// tag::http-basic[]
				mvc
					.perform(get("/").with(httpBasic("user", "password")))
				// end::http-basic[]
					.andReturn();

		assertThat(result.getRequest().getHeader(HttpHeaders.AUTHORIZATION))
				.isEqualTo("Basic dXNlcjpwYXNzd29yZA==");
	}

	@RestController
	static class TestController {

		@GetMapping("/")
		String index() {
			return "ok";
		}

	}

}
