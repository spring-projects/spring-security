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

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;
import static org.springframework.security.web.servlet.TestMockHttpServletRequests.get;

/**
 * Tests {@link ChannelProcessingFilter}.
 *
 * @author Ben Alex
 */
public class ChannelProcessingFilterTests {

	@Test
	public void testDetectsMissingChannelDecisionManager() {
		ChannelProcessingFilter filter = new ChannelProcessingFilter();
		MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "MOCK");
		filter.setSecurityMetadataSource(fids);
		assertThatIllegalArgumentException().isThrownBy(filter::afterPropertiesSet);
	}

	@Test
	public void testDetectsMissingFilterInvocationSecurityMetadataSource() {
		ChannelProcessingFilter filter = new ChannelProcessingFilter();
		filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "MOCK"));
		assertThatIllegalArgumentException().isThrownBy(filter::afterPropertiesSet);
	}

	@Test
	public void testDetectsSupportedConfigAttribute() {
		ChannelProcessingFilter filter = new ChannelProcessingFilter();
		filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "SUPPORTS_MOCK_ONLY"));
		MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true,
				"SUPPORTS_MOCK_ONLY");
		filter.setSecurityMetadataSource(fids);
		filter.afterPropertiesSet();
	}

	@Test
	public void testDetectsUnsupportedConfigAttribute() {
		ChannelProcessingFilter filter = new ChannelProcessingFilter();
		filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "SUPPORTS_MOCK_ONLY"));
		MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true,
				"SUPPORTS_MOCK_ONLY", "INVALID_ATTRIBUTE");
		filter.setSecurityMetadataSource(fids);
		assertThatIllegalArgumentException().isThrownBy(filter::afterPropertiesSet);
	}

	@Test
	public void testDoFilterWhenManagerDoesCommitResponse() throws Exception {
		ChannelProcessingFilter filter = new ChannelProcessingFilter();
		filter.setChannelDecisionManager(new MockChannelDecisionManager(true, "SOME_ATTRIBUTE"));
		MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "SOME_ATTRIBUTE");
		filter.setSecurityMetadataSource(fids);
		MockHttpServletRequest request = get("/path").build();
		request.setQueryString("info=now");
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, mock(FilterChain.class));
	}

	@Test
	public void testDoFilterWhenManagerDoesNotCommitResponse() throws Exception {
		ChannelProcessingFilter filter = new ChannelProcessingFilter();
		filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "SOME_ATTRIBUTE"));
		MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "SOME_ATTRIBUTE");
		filter.setSecurityMetadataSource(fids);
		MockHttpServletRequest request = get("/path").build();
		request.setQueryString("info=now");
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, mock(FilterChain.class));
	}

	@Test
	public void testDoFilterWhenNullConfigAttributeReturned() throws Exception {
		ChannelProcessingFilter filter = new ChannelProcessingFilter();
		filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "NOT_USED"));
		MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", true, "NOT_USED");
		filter.setSecurityMetadataSource(fids);
		MockHttpServletRequest request = get("/PATH_NOT_MATCHING_CONFIG_ATTRIBUTE").build();
		request.setQueryString("info=now");
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, mock(FilterChain.class));
	}

	@Test
	public void testGetterSetters() {
		ChannelProcessingFilter filter = new ChannelProcessingFilter();
		filter.setChannelDecisionManager(new MockChannelDecisionManager(false, "MOCK"));
		assertThat(filter.getChannelDecisionManager() != null).isTrue();
		MockFilterInvocationDefinitionMap fids = new MockFilterInvocationDefinitionMap("/path", false, "MOCK");
		filter.setSecurityMetadataSource(fids);
		assertThat(filter.getSecurityMetadataSource()).isSameAs(fids);
		filter.afterPropertiesSet();
	}

	private class MockChannelDecisionManager implements ChannelDecisionManager {

		private String supportAttribute;

		private boolean commitAResponse;

		MockChannelDecisionManager(boolean commitAResponse, String supportAttribute) {
			this.commitAResponse = commitAResponse;
			this.supportAttribute = supportAttribute;
		}

		@Override
		public void decide(FilterInvocation invocation, Collection<ConfigAttribute> config) throws IOException {
			if (this.commitAResponse) {
				invocation.getHttpResponse().sendRedirect("/redirected");
			}
		}

		@Override
		public boolean supports(ConfigAttribute attribute) {
			return attribute.getAttribute().equals(this.supportAttribute);
		}

	}

	private class MockFilterInvocationDefinitionMap implements FilterInvocationSecurityMetadataSource {

		private Collection<ConfigAttribute> toReturn;

		private String servletPath;

		private boolean provideIterator;

		MockFilterInvocationDefinitionMap(String servletPath, boolean provideIterator, String... toReturn) {
			this.servletPath = servletPath;
			this.toReturn = SecurityConfig.createList(toReturn);
			this.provideIterator = provideIterator;
		}

		@Override
		public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
			FilterInvocation fi = (FilterInvocation) object;
			if (this.servletPath.equals(fi.getHttpRequest().getServletPath())) {
				return this.toReturn;
			}
			else {
				return null;
			}
		}

		@Override
		public Collection<ConfigAttribute> getAllConfigAttributes() {
			if (!this.provideIterator) {
				return null;
			}
			return this.toReturn;
		}

		@Override
		public boolean supports(Class<?> clazz) {
			return true;
		}

	}

}
