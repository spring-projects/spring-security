/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.samples.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.util.ReflectionTestUtils;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.List;
import javax.servlet.Filter;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = SecurityConfig.class)
public class SecurityConfigTests {

	@Autowired
	ApplicationContext context;

	@Test
	public void securityConfigurationLoads() {
	}

	@Test
	public void filterWhenLoginProcessingUrlIsSetInJavaConfigThenTheFilterHasIt() {
		FilterChainProxy filterChain = context.getBean(FilterChainProxy.class);
		Assert.assertNotNull(filterChain);
		final List<Filter> filters = filterChain.getFilters("/sample/jc/saml2/sso/test-id");
		Assert.assertNotNull(filters);
		Saml2WebSsoAuthenticationFilter filter = (Saml2WebSsoAuthenticationFilter) filters
				.stream()
				.filter(
						f -> f instanceof Saml2WebSsoAuthenticationFilter
				)
				.findFirst()
				.get();
		for (String field : Arrays.asList("requiresAuthenticationRequestMatcher")) {
			final Object matcher = ReflectionTestUtils.getField(filter, field);
			final Object pattern = ReflectionTestUtils.getField(matcher, "pattern");
			Assert.assertEquals("loginProcessingUrl mismatch", "/sample/jc/saml2/sso/{registrationId}", pattern);
		}
	}
}
