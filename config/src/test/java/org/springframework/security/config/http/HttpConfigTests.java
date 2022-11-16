/*
 * Copyright 2002-2022 the original author or authors.
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

import java.util.Iterator;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class HttpConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/HttpConfigTests";

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void getWhenUsingMinimalConfigurationThenRedirectsToLogin() throws Exception {
		this.spring.configLocations(this.xml("Minimal")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
		// @formatter:on
	}

	@Test
	public void getWhenUsingMinimalAuthorizationManagerThenRedirectsToLogin() throws Exception {
		this.spring.configLocations(this.xml("MinimalAuthorizationManager")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
		// @formatter:on
	}

	@Test
	public void getWhenUsingAuthorizationManagerThenRedirectsToLogin() throws Exception {
		this.spring.configLocations(this.xml("AuthorizationManager")).autowire();
		AuthorizationManager<HttpServletRequest> authorizationManager = this.spring.getContext()
				.getBean(AuthorizationManager.class);
		given(authorizationManager.check(any(), any())).willReturn(new AuthorizationDecision(false));
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
		// @formatter:on
		verify(authorizationManager).check(any(), any());
	}

	@Test
	public void getWhenUsingMinimalConfigurationThenPreventsSessionAsUrlParameter() throws Exception {
		this.spring.configLocations(this.xml("Minimal")).autowire();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChainProxy proxy = this.spring.getContext().getBean(FilterChainProxy.class);
		proxy.doFilter(request, new EncodeUrlDenyingHttpServletResponseWrapper(response), (req, resp) -> {
		});
		assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_MOVED_TEMPORARILY);
		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost/login");
	}

	@Test
	public void getWhenUsingObservationRegistryThenObservesRequest() throws Exception {
		this.spring.configLocations(this.xml("WithObservationRegistry")).autowire();
		// @formatter:off
		this.mvc.perform(get("/").with(httpBasic("user", "password")))
				.andExpect(status().isNotFound());
		// @formatter:on
		ObservationHandler<Observation.Context> handler = this.spring.getContext().getBean(ObservationHandler.class);
		ArgumentCaptor<Observation.Context> captor = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, times(5)).onStart(captor.capture());
		Iterator<Observation.Context> contexts = captor.getAllValues().iterator();
		assertThat(contexts.next().getContextualName()).isEqualTo("security filterchain before");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.authentications");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.authorizations");
		assertThat(contexts.next().getName()).isEqualTo("spring.security.http.secured.requests");
		assertThat(contexts.next().getContextualName()).isEqualTo("security filterchain after");
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	private static class EncodeUrlDenyingHttpServletResponseWrapper extends HttpServletResponseWrapper {

		EncodeUrlDenyingHttpServletResponseWrapper(HttpServletResponse response) {
			super(response);
		}

		@Override
		public String encodeURL(String url) {
			throw new RuntimeException("Unexpected invocation of encodeURL");
		}

		@Override
		public String encodeRedirectURL(String url) {
			throw new RuntimeException("Unexpected invocation of encodeURL");
		}

	}

	public static final class MockObservationRegistry implements FactoryBean<ObservationRegistry> {

		private ObservationHandler<Observation.Context> handler = mock(ObservationHandler.class);

		@Override
		public ObservationRegistry getObject() {
			ObservationRegistry registry = ObservationRegistry.create();
			registry.observationConfig().observationHandler(this.handler);
			given(this.handler.supportsContext(any())).willReturn(true);
			return registry;
		}

		@Override
		public Class<?> getObjectType() {
			return ObservationRegistry.class;
		}

		public void setHandler(ObservationHandler<Observation.Context> handler) {
			this.handler = handler;
		}

	}

}
