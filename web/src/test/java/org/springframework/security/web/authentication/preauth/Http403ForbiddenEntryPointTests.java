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
package org.springframework.security.web.authentication.preauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

public class Http403ForbiddenEntryPointTests {

	public void testCommence() {
		MockHttpServletRequest req = new MockHttpServletRequest();
		MockHttpServletResponse resp = new MockHttpServletResponse();
		Http403ForbiddenEntryPoint fep = new Http403ForbiddenEntryPoint();
		try {
			fep.commence(req, resp,
					new AuthenticationCredentialsNotFoundException("test"));
			assertThat(resp.getStatus()).withFailMessage("Incorrect status").isEqualTo(
					HttpServletResponse.SC_FORBIDDEN);
		}
		catch (IOException e) {
			fail("Unexpected exception thrown: " + e);
		}
		catch (ServletException e) {
			fail("Unexpected exception thrown: " + e);
		}
	}
}
