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
package org.springframework.security.web.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import java.util.HashMap;

/**
 * @author Luke Taylor
 */
public class ExceptionMappingAuthenticationFailureHandlerTests {

	@Test
	public void defaultTargetUrlIsUsedIfNoMappingExists() throws Exception {
		ExceptionMappingAuthenticationFailureHandler fh = new ExceptionMappingAuthenticationFailureHandler();
		fh.setDefaultFailureUrl("/failed");
		MockHttpServletResponse response = new MockHttpServletResponse();
		fh.onAuthenticationFailure(new MockHttpServletRequest(), response,
				new BadCredentialsException(""));

		assertThat(response.getRedirectedUrl()).isEqualTo("/failed");
	}

	@Test
	public void exceptionMapIsUsedIfMappingExists() throws Exception {
		ExceptionMappingAuthenticationFailureHandler fh = new ExceptionMappingAuthenticationFailureHandler();
		HashMap<String, String> mapping = new HashMap<>();
		mapping.put(
				"org.springframework.security.authentication.BadCredentialsException",
				"/badcreds");
		fh.setExceptionMappings(mapping);
		fh.setDefaultFailureUrl("/failed");
		MockHttpServletResponse response = new MockHttpServletResponse();
		fh.onAuthenticationFailure(new MockHttpServletRequest(), response,
				new BadCredentialsException(""));

		assertThat(response.getRedirectedUrl()).isEqualTo("/badcreds");
	}

}
