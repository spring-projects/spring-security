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

package org.springframework.security.web.firewall;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Luke Taylor
 */
public class DefaultHttpFirewallTests {

	public String[] unnormalizedPaths = { "/..", "/./path/", "/path/path/.", "/path/path//.", "./path/../path//.",
			"./path", ".//path", "." };

	@Test
	public void unnormalizedPathsAreRejected() {
		DefaultHttpFirewall fw = new DefaultHttpFirewall();
		for (String path : this.unnormalizedPaths) {
			MockHttpServletRequest request = new MockHttpServletRequest();
			request.setServletPath(path);
			assertThatExceptionOfType(RequestRejectedException.class)
					.isThrownBy(() -> fw.getFirewalledRequest(request));
			request.setPathInfo(path);
			assertThatExceptionOfType(RequestRejectedException.class)
					.isThrownBy(() -> fw.getFirewalledRequest(request));
		}
	}

	/**
	 * On WebSphere 8.5 a URL like /context-root/a/b;%2f1/c can bypass a rule on /a/b/c
	 * because the pathInfo is /a/b;/1/c which ends up being /a/b/1/c while Spring MVC
	 * will strip the ; content from requestURI before the path is URL decoded.
	 */
	@Test(expected = RequestRejectedException.class)
	public void getFirewalledRequestWhenLowercaseEncodedPathThenException() {
		DefaultHttpFirewall fw = new DefaultHttpFirewall();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/context-root/a/b;%2f1/c");
		request.setContextPath("/context-root");
		request.setServletPath("");
		request.setPathInfo("/a/b;/1/c"); // URL decoded requestURI
		fw.getFirewalledRequest(request);
	}

	@Test(expected = RequestRejectedException.class)
	public void getFirewalledRequestWhenUppercaseEncodedPathThenException() {
		DefaultHttpFirewall fw = new DefaultHttpFirewall();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/context-root/a/b;%2F1/c");
		request.setContextPath("/context-root");
		request.setServletPath("");
		request.setPathInfo("/a/b;/1/c"); // URL decoded requestURI
		fw.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenAllowUrlEncodedSlashAndLowercaseEncodedPathThenNoException() {
		DefaultHttpFirewall fw = new DefaultHttpFirewall();
		fw.setAllowUrlEncodedSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/context-root/a/b;%2f1/c");
		request.setContextPath("/context-root");
		request.setServletPath("");
		request.setPathInfo("/a/b;/1/c"); // URL decoded requestURI
		fw.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenAllowUrlEncodedSlashAndUppercaseEncodedPathThenNoException() {
		DefaultHttpFirewall fw = new DefaultHttpFirewall();
		fw.setAllowUrlEncodedSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("/context-root/a/b;%2F1/c");
		request.setContextPath("/context-root");
		request.setServletPath("");
		request.setPathInfo("/a/b;/1/c"); // URL decoded requestURI
		fw.getFirewalledRequest(request);
	}

}
