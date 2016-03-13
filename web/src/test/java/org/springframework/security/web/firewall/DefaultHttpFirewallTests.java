/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.firewall;

import static org.assertj.core.api.Assertions.fail;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * @author Luke Taylor
 */
public class DefaultHttpFirewallTests {
	public String[] unnormalizedPaths = { "/..", "/./path/", "/path/path/.",
			"/path/path//.", "./path/../path//.", "./path", ".//path", "." };

	@Test
	public void unnormalizedPathsAreRejected() throws Exception {
		DefaultHttpFirewall fw = new DefaultHttpFirewall();

		MockHttpServletRequest request;
		for (String path : unnormalizedPaths) {
			request = new MockHttpServletRequest();
			request.setServletPath(path);
			try {
				fw.getFirewalledRequest(request);
				fail(path + " is un-normalized");
			}
			catch (RequestRejectedException expected) {
			}
			request.setPathInfo(path);
			try {
				fw.getFirewalledRequest(request);
				fail(path + " is un-normalized");
			}
			catch (RequestRejectedException expected) {
			}
		}
	}
}
