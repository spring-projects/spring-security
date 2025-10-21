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

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import jakarta.servlet.FilterChain;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.mock;

/**
 * Tests {@link ChannelDecisionManagerImpl}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("unchecked")
public class ChannelDecisionManagerImplTests {

	@Test
	public void testCannotSetEmptyChannelProcessorsList() throws Exception {
		ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
		assertThatIllegalArgumentException().isThrownBy(() -> {
			cdm.setChannelProcessors(new Vector());
			cdm.afterPropertiesSet();
		}).withMessage("A list of ChannelProcessors is required");
	}

	@Test
	public void testCannotSetIncorrectObjectTypesIntoChannelProcessorsList() {
		ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
		List list = new Vector();
		list.add("THIS IS NOT A CHANNELPROCESSOR");
		assertThatIllegalArgumentException().isThrownBy(() -> cdm.setChannelProcessors(list));
	}

	@Test
	public void testCannotSetNullChannelProcessorsList() throws Exception {
		ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
		assertThatIllegalArgumentException().isThrownBy(() -> {
			cdm.setChannelProcessors(null);
			cdm.afterPropertiesSet();
		}).withMessage("A list of ChannelProcessors is required");
	}

	@Test
	public void testDecideIsOperational() throws Exception {
		ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
		MockChannelProcessor cpXyz = new MockChannelProcessor("xyz", false);
		MockChannelProcessor cpAbc = new MockChannelProcessor("abc", true);
		List list = new Vector();
		list.add(cpXyz);
		list.add(cpAbc);
		cdm.setChannelProcessors(list);
		cdm.afterPropertiesSet();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterInvocation fi = new FilterInvocation(request, response, mock(FilterChain.class));
		List<ConfigAttribute> cad = SecurityConfig.createList("xyz");
		cdm.decide(fi, cad);
		Assertions.assertThat(fi.getResponse().isCommitted()).isTrue();
	}

	@Test
	public void testAnyChannelAttributeCausesProcessorsToBeSkipped() throws Exception {
		ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
		MockChannelProcessor cpAbc = new MockChannelProcessor("abc", true);
		List list = new Vector();
		list.add(cpAbc);
		cdm.setChannelProcessors(list);
		cdm.afterPropertiesSet();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterInvocation fi = new FilterInvocation(request, response, mock(FilterChain.class));
		cdm.decide(fi, SecurityConfig.createList(new String[] { "abc", "ANY_CHANNEL" }));
		Assertions.assertThat(fi.getResponse().isCommitted()).isFalse();
	}

	@Test
	public void testDecideIteratesAllProcessorsIfNoneCommitAResponse() throws Exception {
		ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
		MockChannelProcessor cpXyz = new MockChannelProcessor("xyz", false);
		MockChannelProcessor cpAbc = new MockChannelProcessor("abc", false);
		List list = new Vector();
		list.add(cpXyz);
		list.add(cpAbc);
		cdm.setChannelProcessors(list);
		cdm.afterPropertiesSet();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterInvocation fi = new FilterInvocation(request, response, mock(FilterChain.class));
		cdm.decide(fi, SecurityConfig.createList("SOME_ATTRIBUTE_NO_PROCESSORS_SUPPORT"));
		Assertions.assertThat(fi.getResponse().isCommitted()).isFalse();
	}

	@Test
	public void testDelegatesSupports() throws Exception {
		ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
		MockChannelProcessor cpXyz = new MockChannelProcessor("xyz", false);
		MockChannelProcessor cpAbc = new MockChannelProcessor("abc", false);
		List list = new Vector();
		list.add(cpXyz);
		list.add(cpAbc);
		cdm.setChannelProcessors(list);
		cdm.afterPropertiesSet();
		assertThat(cdm.supports(new SecurityConfig("xyz"))).isTrue();
		assertThat(cdm.supports(new SecurityConfig("abc"))).isTrue();
		assertThat(cdm.supports(new SecurityConfig("UNSUPPORTED"))).isFalse();
	}

	@Test
	public void testGettersSetters() {
		ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
		assertThat(cdm.getChannelProcessors()).isNull();
		MockChannelProcessor cpXyz = new MockChannelProcessor("xyz", false);
		MockChannelProcessor cpAbc = new MockChannelProcessor("abc", false);
		List list = new Vector();
		list.add(cpXyz);
		list.add(cpAbc);
		cdm.setChannelProcessors(list);
		assertThat(cdm.getChannelProcessors()).isEqualTo(list);
	}

	@Test
	public void testStartupFailsWithEmptyChannelProcessorsList() throws Exception {
		ChannelDecisionManagerImpl cdm = new ChannelDecisionManagerImpl();
		assertThatIllegalArgumentException().isThrownBy(cdm::afterPropertiesSet)
			.withMessage("A list of ChannelProcessors is required");
	}

	private class MockChannelProcessor implements ChannelProcessor {

		private String configAttribute;

		private boolean failIfCalled;

		MockChannelProcessor(String configAttribute, boolean failIfCalled) {
			this.configAttribute = configAttribute;
			this.failIfCalled = failIfCalled;
		}

		@Override
		public void decide(FilterInvocation invocation, Collection<ConfigAttribute> config) throws IOException {
			Iterator iter = config.iterator();
			if (this.failIfCalled) {
				fail("Should not have called this channel processor: " + this.configAttribute);
			}
			while (iter.hasNext()) {
				ConfigAttribute attr = (ConfigAttribute) iter.next();
				if (attr.getAttribute().equals(this.configAttribute)) {
					invocation.getHttpResponse().sendRedirect("/redirected");
					return;
				}
			}
		}

		@Override
		public boolean supports(ConfigAttribute attribute) {
			return attribute.getAttribute().equals(this.configAttribute);
		}

	}

}
