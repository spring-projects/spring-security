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

package org.springframework.security.config.annotation.web.configurers.openid;

import java.util.List;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Rule;
import org.junit.Test;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.message.AuthRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationFilter;
import org.springframework.security.openid.OpenIDAuthenticationProvider;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.openid4java.discovery.yadis.YadisResolver.YADIS_XRDS_LOCATION;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link OpenIDLoginConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
public class OpenIDLoginConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnOpenIDAuthenticationFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(OpenIDAuthenticationFilter.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnOpenIDAuthenticationProvider() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(OpenIDAuthenticationProvider.class));
	}

	@Test
	public void openidLoginWhenInvokedTwiceThenUsesOriginalLoginPage() throws Exception {
		this.spring.register(InvokeTwiceDoesNotOverrideConfig.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login/custom"));
	}

	@Test
	public void requestWhenOpenIdLoginPageInLambdaThenRedirectsToLoginPAge() throws Exception {
		this.spring.register(OpenIdLoginPageInLambdaConfig.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login/custom"));
	}

	@Test
	public void requestWhenAttributeExchangeConfiguredThenFetchAttributesMatchAttributeList() throws Exception {
		OpenIdAttributesInLambdaConfig.CONSUMER_MANAGER = mock(ConsumerManager.class);
		AuthRequest mockAuthRequest = mock(AuthRequest.class);
		DiscoveryInformation mockDiscoveryInformation = mock(DiscoveryInformation.class);
		given(mockAuthRequest.getDestinationUrl(anyBoolean())).willReturn("mockUrl");
		given(OpenIdAttributesInLambdaConfig.CONSUMER_MANAGER.associate(any())).willReturn(mockDiscoveryInformation);
		given(OpenIdAttributesInLambdaConfig.CONSUMER_MANAGER.authenticate(any(DiscoveryInformation.class), any(),
				any())).willReturn(mockAuthRequest);
		this.spring.register(OpenIdAttributesInLambdaConfig.class).autowire();

		try (MockWebServer server = new MockWebServer()) {
			String endpoint = server.url("/").toString();

			server.enqueue(new MockResponse().addHeader(YADIS_XRDS_LOCATION, endpoint));
			server.enqueue(new MockResponse()
					.setBody(String.format("<XRDS><XRD><Service><URI>%s</URI></Service></XRD></XRDS>", endpoint)));

			MvcResult mvcResult = this.mvc.perform(
					get("/login/openid").param(OpenIDAuthenticationFilter.DEFAULT_CLAIMED_IDENTITY_FIELD, endpoint))
					.andExpect(status().isFound()).andReturn();

			Object attributeObject = mvcResult.getRequest().getSession()
					.getAttribute("SPRING_SECURITY_OPEN_ID_ATTRIBUTES_FETCH_LIST");
			assertThat(attributeObject).isInstanceOf(List.class);
			List<OpenIDAttribute> attributeList = (List<OpenIDAttribute>) attributeObject;
			assertThat(
					attributeList.stream()
							.anyMatch(attribute -> "nickname".equals(attribute.getName())
									&& "https://schema.openid.net/namePerson/friendly".equals(attribute.getType())))
											.isTrue();
			assertThat(attributeList.stream()
					.anyMatch(attribute -> "email".equals(attribute.getName())
							&& "https://schema.openid.net/contact/email".equals(attribute.getType())
							&& attribute.isRequired() && attribute.getCount() == 2)).isTrue();
		}
	}

	@Test
	public void requestWhenAttributeNameNotSpecifiedThenAttributeNameDefaulted() throws Exception {
		OpenIdAttributesNullNameConfig.CONSUMER_MANAGER = mock(ConsumerManager.class);
		AuthRequest mockAuthRequest = mock(AuthRequest.class);
		DiscoveryInformation mockDiscoveryInformation = mock(DiscoveryInformation.class);
		given(mockAuthRequest.getDestinationUrl(anyBoolean())).willReturn("mockUrl");
		given(OpenIdAttributesNullNameConfig.CONSUMER_MANAGER.associate(any())).willReturn(mockDiscoveryInformation);
		given(OpenIdAttributesNullNameConfig.CONSUMER_MANAGER.authenticate(any(DiscoveryInformation.class), any(),
				any())).willReturn(mockAuthRequest);
		this.spring.register(OpenIdAttributesNullNameConfig.class).autowire();

		try (MockWebServer server = new MockWebServer()) {
			String endpoint = server.url("/").toString();

			server.enqueue(new MockResponse().addHeader(YADIS_XRDS_LOCATION, endpoint));
			server.enqueue(new MockResponse()
					.setBody(String.format("<XRDS><XRD><Service><URI>%s</URI></Service></XRD></XRDS>", endpoint)));

			MvcResult mvcResult = this.mvc.perform(
					get("/login/openid").param(OpenIDAuthenticationFilter.DEFAULT_CLAIMED_IDENTITY_FIELD, endpoint))
					.andExpect(status().isFound()).andReturn();

			Object attributeObject = mvcResult.getRequest().getSession()
					.getAttribute("SPRING_SECURITY_OPEN_ID_ATTRIBUTES_FETCH_LIST");
			assertThat(attributeObject).isInstanceOf(List.class);
			List<OpenIDAttribute> attributeList = (List<OpenIDAttribute>) attributeObject;
			assertThat(attributeList).hasSize(1);
			assertThat(attributeList.get(0).getName()).isEqualTo("default-attribute");
		}
	}

	@EnableWebSecurity
	static class ObjectPostProcessorConfig extends WebSecurityConfigurerAdapter {

		static ObjectPostProcessor<Object> objectPostProcessor;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.openidLogin();
			// @formatter:on
		}

		@Bean
		static ObjectPostProcessor<Object> objectPostProcessor() {
			return objectPostProcessor;
		}

	}

	static class ReflectingObjectPostProcessor implements ObjectPostProcessor<Object> {

		@Override
		public <O> O postProcess(O object) {
			return object;
		}

	}

	@EnableWebSecurity
	static class InvokeTwiceDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.openidLogin()
					.loginPage("/login/custom")
					.and()
				.openidLogin();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class OpenIdLoginPageInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.openidLogin(openIdLogin ->
					openIdLogin
						.loginPage("/login/custom")
				);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class OpenIdAttributesInLambdaConfig extends WebSecurityConfigurerAdapter {

		static ConsumerManager CONSUMER_MANAGER;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().permitAll()
				)
				.openidLogin(openIdLogin ->
					openIdLogin
						.consumerManager(CONSUMER_MANAGER)
						.attributeExchange(attributeExchange ->
								attributeExchange
									.identifierPattern(".*")
									.attribute(nicknameAttribute ->
										nicknameAttribute
											.name("nickname")
											.type("https://schema.openid.net/namePerson/friendly")
									)
									.attribute(emailAttribute ->
										emailAttribute
											.name("email")
											.type("https://schema.openid.net/contact/email")
											.required(true)
											.count(2)
									)
						)
				);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class OpenIdAttributesNullNameConfig extends WebSecurityConfigurerAdapter {

		static ConsumerManager CONSUMER_MANAGER;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().permitAll()
				)
				.openidLogin(openIdLogin ->
					openIdLogin
							.consumerManager(CONSUMER_MANAGER)
						.attributeExchange(attributeExchange ->
								attributeExchange
									.identifierPattern(".*")
									.attribute(withDefaults())
						)
				);
			// @formatter:on
		}

	}

}
