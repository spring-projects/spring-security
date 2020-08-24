/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.access.channel;

import javax.servlet.FilterChain;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.mock;

/**
 * Tests {@link SecureChannelProcessor}.
 *
 * @author Ben Alex
 */
public class SecureChannelProcessorTests {

	@Test
	public void testDecideDetectsAcceptableChannel() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("info=true");
		request.setServerName("localhost");
		request.setContextPath("/bigapp");
		request.setServletPath("/servlet");
		request.setScheme("https");
		request.setSecure(true);
		request.setServerPort(8443);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterInvocation fi = new FilterInvocation(request, response, mock(FilterChain.class));
		SecureChannelProcessor processor = new SecureChannelProcessor();
		processor.decide(fi, SecurityConfig.createList("SOME_IGNORED_ATTRIBUTE", "REQUIRES_SECURE_CHANNEL"));
		assertThat(fi.getResponse().isCommitted()).isFalse();
	}

	@Test
	public void testDecideDetectsUnacceptableChannel() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("info=true");
		request.setServerName("localhost");
		request.setContextPath("/bigapp");
		request.setServletPath("/servlet");
		request.setScheme("http");
		request.setServerPort(8080);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterInvocation fi = new FilterInvocation(request, response, mock(FilterChain.class));
		SecureChannelProcessor processor = new SecureChannelProcessor();
		processor.decide(fi,
				SecurityConfig.createList(new String[] { "SOME_IGNORED_ATTRIBUTE", "REQUIRES_SECURE_CHANNEL" }));
		assertThat(fi.getResponse().isCommitted()).isTrue();
	}

	@Test
	public void testDecideRejectsNulls() throws Exception {
		SecureChannelProcessor processor = new SecureChannelProcessor();
		processor.afterPropertiesSet();
		try {
			processor.decide(null, null);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}
	}

	@Test
	public void testGettersSetters() {
		SecureChannelProcessor processor = new SecureChannelProcessor();
		assertThat(processor.getSecureKeyword()).isEqualTo("REQUIRES_SECURE_CHANNEL");
		processor.setSecureKeyword("X");
		assertThat(processor.getSecureKeyword()).isEqualTo("X");
		assertThat(processor.getEntryPoint() != null).isTrue();
		processor.setEntryPoint(null);
		assertThat(processor.getEntryPoint() == null).isTrue();
	}

	@Test
	public void testMissingEntryPoint() throws Exception {
		SecureChannelProcessor processor = new SecureChannelProcessor();
		processor.setEntryPoint(null);
		try {
			processor.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(expected.getMessage()).isEqualTo("entryPoint required");
		}
	}

	@Test
	public void testMissingSecureChannelKeyword() throws Exception {
		SecureChannelProcessor processor = new SecureChannelProcessor();
		processor.setSecureKeyword(null);
		try {
			processor.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(expected.getMessage()).isEqualTo("secureKeyword required");
		}
		processor.setSecureKeyword("");
		try {
			processor.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(expected.getMessage()).isEqualTo("secureKeyword required");
		}
	}

	@Test
	public void testSupports() {
		SecureChannelProcessor processor = new SecureChannelProcessor();
		assertThat(processor.supports(new SecurityConfig("REQUIRES_SECURE_CHANNEL"))).isTrue();
		assertThat(processor.supports(null)).isFalse();
		assertThat(processor.supports(new SecurityConfig("NOT_SUPPORTED"))).isFalse();
	}

}
