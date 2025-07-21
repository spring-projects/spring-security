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

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;
import static org.springframework.security.web.servlet.TestMockHttpServletRequests.get;

/**
 * Tests {@link SecureChannelProcessor}.
 *
 * @author Ben Alex
 */
public class SecureChannelProcessorTests {

	@Test
	public void testDecideDetectsAcceptableChannel() throws Exception {
		MockHttpServletRequest request = get("https://localhost:8443").requestUri("/bigapp", "/servlet", null)
			.queryString("info=true")
			.build();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterInvocation fi = new FilterInvocation(request, response, mock(FilterChain.class));
		SecureChannelProcessor processor = new SecureChannelProcessor();
		processor.decide(fi, SecurityConfig.createList("SOME_IGNORED_ATTRIBUTE", "REQUIRES_SECURE_CHANNEL"));
		assertThat(fi.getResponse().isCommitted()).isFalse();
	}

	@Test
	public void testDecideDetectsUnacceptableChannel() throws Exception {
		MockHttpServletRequest request = get("http://localhost:8080").requestUri("/bigapp", "/servlet", null)
			.queryString("info=true")
			.build();
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
		assertThatIllegalArgumentException().isThrownBy(() -> processor.decide(null, null));
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
		assertThatIllegalArgumentException().isThrownBy(processor::afterPropertiesSet)
			.withMessage("entryPoint required");
	}

	@Test
	public void testMissingSecureChannelKeyword() throws Exception {
		SecureChannelProcessor processor = new SecureChannelProcessor();
		processor.setSecureKeyword(null);
		assertThatIllegalArgumentException().isThrownBy(processor::afterPropertiesSet)
			.withMessage("secureKeyword required");
		processor.setSecureKeyword("");
		assertThatIllegalArgumentException().isThrownBy(() -> processor.afterPropertiesSet())
			.withMessage("secureKeyword required");
	}

	@Test
	public void testSupports() {
		SecureChannelProcessor processor = new SecureChannelProcessor();
		assertThat(processor.supports(new SecurityConfig("REQUIRES_SECURE_CHANNEL"))).isTrue();
		assertThat(processor.supports(null)).isFalse();
		assertThat(processor.supports(new SecurityConfig("NOT_SUPPORTED"))).isFalse();
	}

}
