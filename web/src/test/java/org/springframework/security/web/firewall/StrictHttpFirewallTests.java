/*
 * Copyright 2012-2020 the original author or authors.
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

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Rob Winch
 * @author Eddú Meléndez
 */
public class StrictHttpFirewallTests {

	public String[] unnormalizedPaths = { "/..", "/./path/", "/path/path/.", "/path/path//.", "./path/../path//.",
			"./path", ".//path", ".", "//path", "//path/path", "//path//path", "/path//path" };

	private StrictHttpFirewall firewall = new StrictHttpFirewall();

	private MockHttpServletRequest request = new MockHttpServletRequest("GET", "");

	@Test
	public void getFirewalledRequestWhenInvalidMethodThenThrowsRequestRejectedException() {
		this.request.setMethod("INVALID");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	// blocks XST attacks
	@Test
	public void getFirewalledRequestWhenTraceMethodThenThrowsRequestRejectedException() {
		this.request.setMethod(HttpMethod.TRACE.name());
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	// blocks XST attack if request is forwarded to a Microsoft IIS web server
	public void getFirewalledRequestWhenTrackMethodThenThrowsRequestRejectedException() {
		this.request.setMethod("TRACK");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	// HTTP methods are case sensitive
	public void getFirewalledRequestWhenLowercaseGetThenThrowsRequestRejectedException() {
		this.request.setMethod("get");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenAllowedThenNoException() {
		List<String> allowedMethods = Arrays.asList("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT");
		for (String allowedMethod : allowedMethods) {
			this.request = new MockHttpServletRequest(allowedMethod, "");
			this.firewall.getFirewalledRequest(this.request);
		}
	}

	@Test
	public void getFirewalledRequestWhenInvalidMethodAndAnyMethodThenNoException() {
		this.firewall.setUnsafeAllowAnyHttpMethod(true);
		this.request.setMethod("INVALID");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenRequestURINotNormalizedThenThrowsRequestRejectedException() {
		for (String path : this.unnormalizedPaths) {
			this.request = new MockHttpServletRequest("GET", "");
			this.request.setRequestURI(path);
			assertThatExceptionOfType(RequestRejectedException.class)
					.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
		}
	}

	@Test
	public void getFirewalledRequestWhenContextPathNotNormalizedThenThrowsRequestRejectedException() {
		for (String path : this.unnormalizedPaths) {
			this.request = new MockHttpServletRequest("GET", "");
			this.request.setContextPath(path);
			assertThatExceptionOfType(RequestRejectedException.class)
					.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
		}
	}

	@Test
	public void getFirewalledRequestWhenServletPathNotNormalizedThenThrowsRequestRejectedException() {
		for (String path : this.unnormalizedPaths) {
			this.request = new MockHttpServletRequest("GET", "");
			this.request.setServletPath(path);
			assertThatExceptionOfType(RequestRejectedException.class)
					.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
		}
	}

	@Test
	public void getFirewalledRequestWhenPathInfoNotNormalizedThenThrowsRequestRejectedException() {
		for (String path : this.unnormalizedPaths) {
			this.request = new MockHttpServletRequest("GET", "");
			this.request.setPathInfo(path);
			assertThatExceptionOfType(RequestRejectedException.class)
					.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
		}
	}

	@Test
	public void getFirewalledRequestWhenSemicolonInContextPathThenThrowsRequestRejectedException() {
		this.request.setContextPath(";/context");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenSemicolonInServletPathThenThrowsRequestRejectedException() {
		this.request.setServletPath("/spring;/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenSemicolonInPathInfoThenThrowsRequestRejectedException() {
		this.request.setPathInfo("/path;/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenSemicolonInRequestUriThenThrowsRequestRejectedException() {
		this.request.setRequestURI("/path;/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenEncodedSemicolonInContextPathThenThrowsRequestRejectedException() {
		this.request.setContextPath("%3B/context");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenEncodedSemicolonInServletPathThenThrowsRequestRejectedException() {
		this.request.setServletPath("/spring%3B/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenEncodedSemicolonInPathInfoThenThrowsRequestRejectedException() {
		this.request.setPathInfo("/path%3B/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenEncodedSemicolonInRequestUriThenThrowsRequestRejectedException() {
		this.request.setRequestURI("/path%3B/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenLowercaseEncodedSemicolonInContextPathThenThrowsRequestRejectedException() {
		this.request.setContextPath("%3b/context");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenLowercaseEncodedSemicolonInServletPathThenThrowsRequestRejectedException() {
		this.request.setServletPath("/spring%3b/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenLowercaseEncodedSemicolonInPathInfoThenThrowsRequestRejectedException() {
		this.request.setPathInfo("/path%3b/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenLowercaseEncodedSemicolonInRequestUriThenThrowsRequestRejectedException() {
		this.request.setRequestURI("/path%3b/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenSemicolonInContextPathAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request.setContextPath(";/context");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenSemicolonInServletPathAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request.setServletPath("/spring;/");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenSemicolonInPathInfoAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request.setPathInfo("/path;/");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenSemicolonInRequestUriAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request.setRequestURI("/path;/");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenEncodedSemicolonInContextPathAndAllowSemicolonThenNoException() {
		this.firewall.setAllowUrlEncodedPercent(true);
		this.firewall.setAllowSemicolon(true);
		this.request.setContextPath("%3B/context");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenEncodedSemicolonInServletPathAndAllowSemicolonThenNoException() {
		this.firewall.setAllowUrlEncodedPercent(true);
		this.firewall.setAllowSemicolon(true);
		this.request.setServletPath("/spring%3B/");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenEncodedSemicolonInPathInfoAndAllowSemicolonThenNoException() {
		this.firewall.setAllowUrlEncodedPercent(true);
		this.firewall.setAllowSemicolon(true);
		this.request.setPathInfo("/path%3B/");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenEncodedSemicolonInRequestUriAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request.setRequestURI("/path%3B/");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenLowercaseEncodedSemicolonInContextPathAndAllowSemicolonThenNoException() {
		this.firewall.setAllowUrlEncodedPercent(true);
		this.firewall.setAllowSemicolon(true);
		this.request.setContextPath("%3b/context");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenLowercaseEncodedSemicolonInServletPathAndAllowSemicolonThenNoException() {
		this.firewall.setAllowUrlEncodedPercent(true);
		this.firewall.setAllowSemicolon(true);
		this.request.setServletPath("/spring%3b/");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenLowercaseEncodedSemicolonInPathInfoAndAllowSemicolonThenNoException() {
		this.firewall.setAllowUrlEncodedPercent(true);
		this.firewall.setAllowSemicolon(true);
		this.request.setPathInfo("/path%3b/");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenLowercaseEncodedSemicolonInRequestUriAndAllowSemicolonThenNoException() {
		this.firewall.setAllowSemicolon(true);
		this.request.setRequestURI("/path%3b/");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenEncodedPeriodInThenThrowsRequestRejectedException() {
		this.request.setRequestURI("/%2E/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenLowercaseEncodedPeriodInThenThrowsRequestRejectedException() {
		this.request.setRequestURI("/%2e/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenAllowEncodedPeriodAndEncodedPeriodInThenNoException() {
		this.firewall.setAllowUrlEncodedPeriod(true);
		this.request.setRequestURI("/%2E/");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenExceedsLowerboundAsciiThenException() {
		this.request.setRequestURI("/\u0019");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenContainsLowerboundAsciiThenNoException() {
		this.request.setRequestURI("/ ");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenContainsUpperboundAsciiThenNoException() {
		this.request.setRequestURI("/~");
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenExceedsUpperboundAsciiThenException() {
		this.request.setRequestURI("/\u007f");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenContainsNullThenException() {
		this.request.setRequestURI("/\0");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenContainsEncodedNullThenException() {
		this.request.setRequestURI("/something%00/");
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	/**
	 * On WebSphere 8.5 a URL like /context-root/a/b;%2f1/c can bypass a rule on /a/b/c
	 * because the pathInfo is /a/b;/1/c which ends up being /a/b/1/c while Spring MVC
	 * will strip the ; content from requestURI before the path is URL decoded.
	 */
	@Test
	public void getFirewalledRequestWhenLowercaseEncodedPathThenException() {
		this.request.setRequestURI("/context-root/a/b;%2f1/c");
		this.request.setContextPath("/context-root");
		this.request.setServletPath("");
		this.request.setPathInfo("/a/b;/1/c"); // URL decoded requestURI
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenUppercaseEncodedPathThenException() {
		this.request.setRequestURI("/context-root/a/b;%2F1/c");
		this.request.setContextPath("/context-root");
		this.request.setServletPath("");
		this.request.setPathInfo("/a/b;/1/c"); // URL decoded requestURI
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestWhenAllowUrlEncodedSlashAndLowercaseEncodedPathThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowSemicolon(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b;%2f1/c");
		request.setContextPath("/context-root");
		request.setServletPath("");
		request.setPathInfo("/a/b;/1/c"); // URL decoded requestURI
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenAllowUrlEncodedSlashAndUppercaseEncodedPathThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowSemicolon(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b;%2F1/c");
		request.setContextPath("/context-root");
		request.setServletPath("");
		request.setPathInfo("/a/b;/1/c"); // URL decoded requestURI
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenAllowUrlLowerCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2f%2fc");
		request.setContextPath("/context-root");
		request.setServletPath("");
		request.setPathInfo("/a/b//c");
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenAllowUrlUpperCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2F%2Fc");
		request.setContextPath("/context-root");
		request.setServletPath("");
		request.setPathInfo("/a/b//c");
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenAllowUrlLowerCaseAndUpperCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2f%2Fc");
		request.setContextPath("/context-root");
		request.setServletPath("");
		request.setPathInfo("/a/b//c");
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenAllowUrlUpperCaseAndLowerCaseEncodedDoubleSlashThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		this.firewall.setAllowUrlEncodedDoubleSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2F%2fc");
		request.setContextPath("/context-root");
		request.setServletPath("");
		request.setPathInfo("/a/b//c");
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenRemoveFromUpperCaseEncodedUrlBlacklistThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2F%2Fc");
		this.firewall.getEncodedUrlBlacklist().removeAll(Arrays.asList("%2F%2F"));
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenRemoveFromLowerCaseEncodedUrlBlacklistThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2f%2fc");
		this.firewall.getEncodedUrlBlacklist().removeAll(Arrays.asList("%2f%2f"));
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenRemoveFromLowerCaseAndUpperCaseEncodedUrlBlacklistThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2f%2Fc");
		this.firewall.getEncodedUrlBlacklist().removeAll(Arrays.asList("%2f%2F"));
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenRemoveFromUpperCaseAndLowerCaseEncodedUrlBlacklistThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2F%2fc");
		this.firewall.getEncodedUrlBlacklist().removeAll(Arrays.asList("%2F%2f"));
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenRemoveFromDecodedUrlBlacklistThenNoException() {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setPathInfo("/a/b//c");
		this.firewall.getDecodedUrlBlacklist().removeAll(Arrays.asList("//"));
		this.firewall.getFirewalledRequest(request);
	}

	// blocklist
	@Test
	public void getFirewalledRequestWhenRemoveFromUpperCaseEncodedUrlBlocklistThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2F%2Fc");
		this.firewall.getEncodedUrlBlocklist().removeAll(Arrays.asList("%2F%2F"));
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenRemoveFromLowerCaseEncodedUrlBlocklistThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2f%2fc");
		this.firewall.getEncodedUrlBlocklist().removeAll(Arrays.asList("%2f%2f"));
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenRemoveFromLowerCaseAndUpperCaseEncodedUrlBlocklistThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2f%2Fc");
		this.firewall.getEncodedUrlBlocklist().removeAll(Arrays.asList("%2f%2F"));
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenRemoveFromUpperCaseAndLowerCaseEncodedUrlBlocklistThenNoException() {
		this.firewall.setAllowUrlEncodedSlash(true);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI("/context-root/a/b%2F%2fc");
		this.firewall.getEncodedUrlBlocklist().removeAll(Arrays.asList("%2F%2f"));
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenRemoveFromDecodedUrlBlocklistThenNoException() {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setPathInfo("/a/b//c");
		this.firewall.getDecodedUrlBlocklist().removeAll(Arrays.asList("//"));
		this.firewall.getFirewalledRequest(request);
	}

	@Test
	public void getFirewalledRequestWhenTrustedDomainThenNoException() {
		this.request.addHeader("Host", "example.org");
		this.firewall.setAllowedHostnames((hostname) -> hostname.equals("example.org"));
		this.firewall.getFirewalledRequest(this.request);
	}

	@Test
	public void getFirewalledRequestWhenUntrustedDomainThenException() {
		this.request.addHeader("Host", "example.org");
		this.firewall.setAllowedHostnames((hostname) -> hostname.equals("myexample.org"));
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> this.firewall.getFirewalledRequest(this.request));
	}

	@Test
	public void getFirewalledRequestGetHeaderWhenNotAllowedHeaderNameThenException() {
		this.firewall.setAllowedHeaderNames((name) -> !name.equals("bad name"));
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(() -> request.getHeader("bad name"));
	}

	@Test
	public void getFirewalledRequestGetHeaderWhenNotAllowedHeaderValueThenException() {
		this.request.addHeader("good name", "bad value");
		this.firewall.setAllowedHeaderValues((value) -> !value.equals("bad value"));
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(() -> request.getHeader("good name"));
	}

	@Test
	public void getFirewalledRequestGetDateHeaderWhenControlCharacterInHeaderNameThenException() {
		this.request.addHeader("Bad\0Name", "some value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(() -> request.getDateHeader("Bad\0Name"));
	}

	@Test
	public void getFirewalledRequestGetIntHeaderWhenControlCharacterInHeaderNameThenException() {
		this.request.addHeader("Bad\0Name", "some value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(() -> request.getIntHeader("Bad\0Name"));
	}

	@Test
	public void getFirewalledRequestGetHeaderWhenControlCharacterInHeaderNameThenException() {
		this.request.addHeader("Bad\0Name", "some value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(() -> request.getHeader("Bad\0Name"));
	}

	@Test
	public void getFirewalledRequestGetHeaderWhenUndefinedCharacterInHeaderNameThenException() {
		this.request.addHeader("Bad\uFFFEName", "some value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(() -> request.getHeader("Bad\uFFFEName"));
	}

	@Test
	public void getFirewalledRequestGetHeadersWhenControlCharacterInHeaderNameThenException() {
		this.request.addHeader("Bad\0Name", "some value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(() -> request.getHeaders("Bad\0Name"));
	}

	@Test
	public void getFirewalledRequestGetHeaderNamesWhenControlCharacterInHeaderNameThenException() {
		this.request.addHeader("Bad\0Name", "some value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> request.getHeaderNames().nextElement());
	}

	@Test
	public void getFirewalledRequestGetHeaderWhenControlCharacterInHeaderValueThenException() {
		this.request.addHeader("Something", "bad\0value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(() -> request.getHeader("Something"));
	}

	@Test
	public void getFirewalledRequestGetHeaderWhenUndefinedCharacterInHeaderValueThenException() {
		this.request.addHeader("Something", "bad\uFFFEvalue");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(() -> request.getHeader("Something"));
	}

	@Test
	public void getFirewalledRequestGetHeadersWhenControlCharacterInHeaderValueThenException() {
		this.request.addHeader("Something", "bad\0value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> request.getHeaders("Something").nextElement());
	}

	@Test
	public void getFirewalledRequestGetParameterWhenControlCharacterInParameterNameThenException() {
		this.request.addParameter("Bad\0Name", "some value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(() -> request.getParameter("Bad\0Name"));
	}

	@Test
	public void getFirewalledRequestGetParameterMapWhenControlCharacterInParameterNameThenException() {
		this.request.addParameter("Bad\0Name", "some value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(request::getParameterMap);
	}

	@Test
	public void getFirewalledRequestGetParameterNamesWhenControlCharacterInParameterNameThenException() {
		this.request.addParameter("Bad\0Name", "some value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(request.getParameterNames()::nextElement);
	}

	@Test
	public void getFirewalledRequestGetParameterNamesWhenUndefinedCharacterInParameterNameThenException() {
		this.request.addParameter("Bad\uFFFEName", "some value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class).isThrownBy(request.getParameterNames()::nextElement);
	}

	@Test
	public void getFirewalledRequestGetParameterValuesWhenNotAllowedInParameterValueThenException() {
		this.firewall.setAllowedParameterValues((value) -> !value.equals("bad value"));
		this.request.addParameter("Something", "bad value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> request.getParameterValues("Something"));
	}

	@Test
	public void getFirewalledRequestGetParameterValuesWhenNotAllowedInParameterNameThenException() {
		this.firewall.setAllowedParameterNames((value) -> !value.equals("bad name"));
		this.request.addParameter("bad name", "good value");
		HttpServletRequest request = this.firewall.getFirewalledRequest(this.request);
		assertThatExceptionOfType(RequestRejectedException.class)
				.isThrownBy(() -> request.getParameterValues("bad name"));
	}

}
