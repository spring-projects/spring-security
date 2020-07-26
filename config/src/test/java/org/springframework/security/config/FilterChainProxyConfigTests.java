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

package org.springframework.security.config;

import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link FilterChainProxy}.
 *
 * @author Carlos Sanchez
 * @author Ben Alex
 */
public class FilterChainProxyConfigTests {

	private ClassPathXmlApplicationContext appCtx;

	@Before
	public void loadContext() {
		System.setProperty("sec1235.pattern1", "/login");
		System.setProperty("sec1235.pattern2", "/logout");
		this.appCtx = new ClassPathXmlApplicationContext("org/springframework/security/util/filtertest-valid.xml");
	}

	@After
	public void closeContext() {
		if (this.appCtx != null) {
			this.appCtx.close();
		}
	}

	@Test
	public void normalOperation() throws Exception {
		FilterChainProxy filterChainProxy = this.appCtx.getBean("filterChain", FilterChainProxy.class);
		doNormalOperation(filterChainProxy);
	}

	@Test
	public void normalOperationWithNewConfig() throws Exception {
		FilterChainProxy filterChainProxy = this.appCtx.getBean("newFilterChainProxy", FilterChainProxy.class);
		filterChainProxy.setFirewall(new DefaultHttpFirewall());
		checkPathAndFilterOrder(filterChainProxy);
		doNormalOperation(filterChainProxy);
	}

	@Test
	public void normalOperationWithNewConfigRegex() throws Exception {
		FilterChainProxy filterChainProxy = this.appCtx.getBean("newFilterChainProxyRegex", FilterChainProxy.class);
		filterChainProxy.setFirewall(new DefaultHttpFirewall());
		checkPathAndFilterOrder(filterChainProxy);
		doNormalOperation(filterChainProxy);
	}

	@Test
	public void normalOperationWithNewConfigNonNamespace() throws Exception {
		FilterChainProxy filterChainProxy = this.appCtx.getBean("newFilterChainProxyNonNamespace",
				FilterChainProxy.class);
		filterChainProxy.setFirewall(new DefaultHttpFirewall());
		checkPathAndFilterOrder(filterChainProxy);
		doNormalOperation(filterChainProxy);
	}

	@Test
	public void pathWithNoMatchHasNoFilters() {
		FilterChainProxy filterChainProxy = this.appCtx.getBean("newFilterChainProxyNoDefaultPath",
				FilterChainProxy.class);
		assertThat(filterChainProxy.getFilters("/nomatch")).isNull();
	}

	// SEC-1235
	@Test
	public void mixingPatternsAndPlaceholdersDoesntCauseOrderingIssues() {
		FilterChainProxy fcp = this.appCtx.getBean("sec1235FilterChainProxy", FilterChainProxy.class);

		List<SecurityFilterChain> chains = fcp.getFilterChains();
		assertThat(getPattern(chains.get(0))).isEqualTo("/login*");
		assertThat(getPattern(chains.get(1))).isEqualTo("/logout");
		assertThat(((DefaultSecurityFilterChain) chains.get(2)).getRequestMatcher() instanceof AnyRequestMatcher)
				.isTrue();
	}

	private String getPattern(SecurityFilterChain chain) {
		return ((AntPathRequestMatcher) ((DefaultSecurityFilterChain) chain).getRequestMatcher()).getPattern();
	}

	private void checkPathAndFilterOrder(FilterChainProxy filterChainProxy) {
		List<Filter> filters = filterChainProxy.getFilters("/foo/blah;x=1");
		assertThat(filters).hasSize(1);
		assertThat(filters.get(0) instanceof SecurityContextHolderAwareRequestFilter).isTrue();

		filters = filterChainProxy.getFilters("/some;x=2,y=3/other/path;z=4/blah");
		assertThat(filters).isNotNull();
		assertThat(filters).hasSize(3);
		assertThat(filters.get(0) instanceof SecurityContextPersistenceFilter).isTrue();
		assertThat(filters.get(1) instanceof SecurityContextHolderAwareRequestFilter).isTrue();
		assertThat(filters.get(2) instanceof SecurityContextHolderAwareRequestFilter).isTrue();

		filters = filterChainProxy.getFilters("/do/not/filter;x=7");
		assertThat(filters).isEmpty();

		filters = filterChainProxy.getFilters("/another/nonspecificmatch");
		assertThat(filters).hasSize(3);
		assertThat(filters.get(0) instanceof SecurityContextPersistenceFilter).isTrue();
		assertThat(filters.get(1) instanceof UsernamePasswordAuthenticationFilter).isTrue();
		assertThat(filters.get(2) instanceof SecurityContextHolderAwareRequestFilter).isTrue();
	}

	private void doNormalOperation(FilterChainProxy filterChainProxy) throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/foo/secure/super/somefile.html");

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);

		filterChainProxy.doFilter(request, response, chain);
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));

		request.setServletPath("/a/path/which/doesnt/match/any/filter.html");
		chain = mock(FilterChain.class);
		filterChainProxy.doFilter(request, response, chain);
		verify(chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

}
