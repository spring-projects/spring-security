/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.config.http;

import java.util.Collection;

import org.junit.After;
import org.junit.Test;

import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.ConfigTestUtils;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link FilterInvocationSecurityMetadataSourceParser}.
 *
 * @author Luke Taylor
 */
public class FilterSecurityMetadataSourceBeanDefinitionParserTests {

	private AbstractXmlApplicationContext appContext;

	@After
	public void closeAppContext() {
		if (this.appContext != null) {
			this.appContext.close();
			this.appContext = null;
		}
	}

	private void setContext(String context) {
		this.appContext = new InMemoryXmlApplicationContext(context);
	}

	@Test
	public void parsingMinimalConfigurationIsSuccessful() {
		setContext("<filter-security-metadata-source id='fids' use-expressions='false'>"
				+ "   <intercept-url pattern='/**' access='ROLE_A'/>" + "</filter-security-metadata-source>");
		DefaultFilterInvocationSecurityMetadataSource fids = (DefaultFilterInvocationSecurityMetadataSource) this.appContext
				.getBean("fids");
		Collection<ConfigAttribute> cad = fids.getAttributes(createFilterInvocation("/anything", "GET"));
		assertThat(cad).contains(new SecurityConfig("ROLE_A"));
	}

	@Test
	public void expressionsAreSupported() {
		setContext("<filter-security-metadata-source id='fids'>"
				+ "   <intercept-url pattern='/**' access=\"hasRole('ROLE_A')\" />"
				+ "</filter-security-metadata-source>");
		ExpressionBasedFilterInvocationSecurityMetadataSource fids = (ExpressionBasedFilterInvocationSecurityMetadataSource) this.appContext
				.getBean("fids");
		ConfigAttribute[] cad = fids.getAttributes(createFilterInvocation("/anything", "GET"))
				.toArray(new ConfigAttribute[0]);
		assertThat(cad).hasSize(1);
		assertThat(cad[0].toString()).isEqualTo("hasRole('ROLE_A')");
	}

	// SEC-1201
	@Test
	public void interceptUrlsSupportPropertyPlaceholders() {
		System.setProperty("secure.url", "/secure");
		System.setProperty("secure.role", "ROLE_A");
		setContext("<b:bean class='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer'/>"
				+ "<filter-security-metadata-source id='fids' use-expressions='false'>"
				+ "   <intercept-url pattern='${secure.url}' access='${secure.role}'/>"
				+ "</filter-security-metadata-source>");
		DefaultFilterInvocationSecurityMetadataSource fids = (DefaultFilterInvocationSecurityMetadataSource) this.appContext
				.getBean("fids");
		Collection<ConfigAttribute> cad = fids.getAttributes(createFilterInvocation("/secure", "GET"));
		assertThat(cad).containsExactly(new SecurityConfig("ROLE_A"));
	}

	@Test
	public void parsingWithinFilterSecurityInterceptorIsSuccessful() {
		setContext("<http auto-config='true' use-expressions='false'/>"
				+ "<b:bean id='fsi' class='org.springframework.security.web.access.intercept.FilterSecurityInterceptor' autowire='byType'>"
				+ "   <b:property name='securityMetadataSource'>"
				+ "       <filter-security-metadata-source use-expressions='false'>"
				+ "           <intercept-url pattern='/secure/extreme/**' access='ROLE_SUPERVISOR'/>"
				+ "           <intercept-url pattern='/secure/**' access='ROLE_USER'/>"
				+ "           <intercept-url pattern='/**' access='ROLE_USER'/>"
				+ "       </filter-security-metadata-source>" + "   </b:property>"
				+ "   <b:property name='authenticationManager' ref='" + BeanIds.AUTHENTICATION_MANAGER + "'/>"
				+ "</b:bean>" + ConfigTestUtils.AUTH_PROVIDER_XML);
	}

	@Test(expected = BeanDefinitionParsingException.class)
	public void parsingInterceptUrlServletPathFails() {
		setContext("<filter-security-metadata-source id='fids' use-expressions='false'>"
				+ "   <intercept-url pattern='/secure' access='ROLE_USER' servlet-path='/spring' />"
				+ "</filter-security-metadata-source>");
	}

	private FilterInvocation createFilterInvocation(String path, String method) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setRequestURI(null);
		request.setMethod(method);
		request.setServletPath(path);
		return new FilterInvocation(request, new MockHttpServletResponse(), new MockFilterChain());
	}

}
