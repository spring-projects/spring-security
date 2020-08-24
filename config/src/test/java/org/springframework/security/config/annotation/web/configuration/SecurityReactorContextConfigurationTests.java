/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import reactor.core.CoreSubscriber;
import reactor.core.publisher.BaseSubscriber;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Operators;
import reactor.test.StepVerifier;
import reactor.util.context.Context;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.SecurityReactorContextConfiguration.SecurityReactorContextSubscriber;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.web.reactive.function.client.MockExchangeFunction;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;

/**
 * Tests for {@link SecurityReactorContextConfiguration}.
 *
 * @author Joe Grandja
 * @since 5.2
 */
public class SecurityReactorContextConfigurationTests {

	private MockHttpServletRequest servletRequest;

	private MockHttpServletResponse servletResponse;

	private Authentication authentication;

	private SecurityReactorContextConfiguration.SecurityReactorContextSubscriberRegistrar subscriberRegistrar = new SecurityReactorContextConfiguration.SecurityReactorContextSubscriberRegistrar();

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Before
	public void setup() {
		this.servletRequest = new MockHttpServletRequest();
		this.servletResponse = new MockHttpServletResponse();
		this.authentication = new TestingAuthenticationToken("principal", "password");
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
		RequestContextHolder.resetRequestAttributes();
	}

	@Test
	public void createSubscriberIfNecessaryWhenSubscriberContextContainsSecurityContextAttributesThenReturnOriginalSubscriber() {
		Context context = Context.of(SecurityReactorContextSubscriber.SECURITY_CONTEXT_ATTRIBUTES, new HashMap<>());
		BaseSubscriber<Object> originalSubscriber = new BaseSubscriber<Object>() {
			@Override
			public Context currentContext() {
				return context;
			}
		};
		CoreSubscriber<Object> resultSubscriber = this.subscriberRegistrar
				.createSubscriberIfNecessary(originalSubscriber);
		assertThat(resultSubscriber).isSameAs(originalSubscriber);
	}

	@Test
	public void createSubscriberIfNecessaryWhenWebSecurityContextAvailableThenCreateWithParentContext() {
		RequestContextHolder
				.setRequestAttributes(new ServletRequestAttributes(this.servletRequest, this.servletResponse));
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		String testKey = "test_key";
		String testValue = "test_value";
		BaseSubscriber<Object> parent = new BaseSubscriber<Object>() {
			@Override
			public Context currentContext() {
				return Context.of(testKey, testValue);
			}
		};
		CoreSubscriber<Object> subscriber = this.subscriberRegistrar.createSubscriberIfNecessary(parent);
		Context resultContext = subscriber.currentContext();
		assertThat(resultContext.getOrEmpty(testKey)).hasValue(testValue);
		Map<Object, Object> securityContextAttributes = resultContext
				.getOrDefault(SecurityReactorContextSubscriber.SECURITY_CONTEXT_ATTRIBUTES, null);
		assertThat(securityContextAttributes).hasSize(3);
		assertThat(securityContextAttributes).contains(entry(HttpServletRequest.class, this.servletRequest),
				entry(HttpServletResponse.class, this.servletResponse),
				entry(Authentication.class, this.authentication));
	}

	@Test
	public void createSubscriberIfNecessaryWhenParentContextContainsSecurityContextAttributesThenUseParentContext() {
		RequestContextHolder
				.setRequestAttributes(new ServletRequestAttributes(this.servletRequest, this.servletResponse));
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		Context parentContext = Context.of(SecurityReactorContextSubscriber.SECURITY_CONTEXT_ATTRIBUTES,
				new HashMap<>());
		BaseSubscriber<Object> parent = new BaseSubscriber<Object>() {
			@Override
			public Context currentContext() {
				return parentContext;
			}
		};
		CoreSubscriber<Object> subscriber = this.subscriberRegistrar.createSubscriberIfNecessary(parent);
		Context resultContext = subscriber.currentContext();
		assertThat(resultContext).isSameAs(parentContext);
	}

	@Test
	public void createSubscriberIfNecessaryWhenNotServletRequestAttributesThenStillCreate() {
		RequestContextHolder.setRequestAttributes(new RequestAttributes() {
			@Override
			public Object getAttribute(String name, int scope) {
				return null;
			}

			@Override
			public void setAttribute(String name, Object value, int scope) {
			}

			@Override
			public void removeAttribute(String name, int scope) {
			}

			@Override
			public String[] getAttributeNames(int scope) {
				return new String[0];
			}

			@Override
			public void registerDestructionCallback(String name, Runnable callback, int scope) {
			}

			@Override
			public Object resolveReference(String key) {
				return null;
			}

			@Override
			public String getSessionId() {
				return null;
			}

			@Override
			public Object getSessionMutex() {
				return null;
			}
		});
		CoreSubscriber<Object> subscriber = this.subscriberRegistrar
				.createSubscriberIfNecessary(Operators.emptySubscriber());
		assertThat(subscriber).isInstanceOf(SecurityReactorContextConfiguration.SecurityReactorContextSubscriber.class);
	}

	@Test
	public void createPublisherWhenLastOperatorAddedThenSecurityContextAttributesAvailable() {
		// Trigger the importing of SecurityReactorContextConfiguration via
		// OAuth2ImportSelector
		this.spring.register(SecurityConfig.class).autowire();
		// Setup for SecurityReactorContextSubscriberRegistrar
		RequestContextHolder
				.setRequestAttributes(new ServletRequestAttributes(this.servletRequest, this.servletResponse));
		SecurityContextHolder.getContext().setAuthentication(this.authentication);
		ClientResponse clientResponseOk = ClientResponse.create(HttpStatus.OK).build();
		// @formatter:off
		ExchangeFilterFunction filter = (req, next) -> Mono.subscriberContext()
				.filter((ctx) -> ctx.hasKey(SecurityReactorContextSubscriber.SECURITY_CONTEXT_ATTRIBUTES))
				.map((ctx) -> ctx.get(SecurityReactorContextSubscriber.SECURITY_CONTEXT_ATTRIBUTES))
				.cast(Map.class)
				.map((attributes) -> {
					if (attributes.containsKey(HttpServletRequest.class)
							&& attributes.containsKey(HttpServletResponse.class)
							&& attributes.containsKey(Authentication.class)) {
						return clientResponseOk;
					}
					else {
						return ClientResponse.create(HttpStatus.NOT_FOUND).build();
					}
				});
		// @formatter:on
		ClientRequest clientRequest = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com")).build();
		MockExchangeFunction exchange = new MockExchangeFunction();
		Map<Object, Object> expectedContextAttributes = new HashMap<>();
		expectedContextAttributes.put(HttpServletRequest.class, this.servletRequest);
		expectedContextAttributes.put(HttpServletResponse.class, this.servletResponse);
		expectedContextAttributes.put(Authentication.class, this.authentication);
		Mono<ClientResponse> clientResponseMono = filter.filter(clientRequest, exchange)
				.flatMap((response) -> filter.filter(clientRequest, exchange));
		// @formatter:off
		StepVerifier.create(clientResponseMono)
				.expectAccessibleContext()
				.contains(SecurityReactorContextSubscriber.SECURITY_CONTEXT_ATTRIBUTES, expectedContextAttributes)
				.then()
				.expectNext(clientResponseOk)
				.verifyComplete();
		// @formatter:on
	}

	@EnableWebSecurity
	static class SecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
		}

	}

}
