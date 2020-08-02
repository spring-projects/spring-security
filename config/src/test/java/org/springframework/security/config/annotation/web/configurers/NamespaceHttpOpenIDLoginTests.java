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

package org.springframework.security.config.annotation.web.configurers;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Rule;
import org.junit.Test;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.yadis.YadisResolver;
import org.openid4java.message.AuthRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.openid.OpenIDAttribute;
import org.springframework.security.openid.OpenIDAuthenticationFilter;
import org.springframework.security.openid.OpenIDAuthenticationStatus;
import org.springframework.security.openid.OpenIDAuthenticationToken;
import org.springframework.security.openid.OpenIDConsumer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of &lt;openid-login&gt; attributes is
 * present
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
public class NamespaceHttpOpenIDLoginTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void openidLoginWhenUsingDefaultsThenMatchesNamespace() throws Exception {
		this.spring.register(OpenIDLoginConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(redirectedUrl("http://localhost/login"));
		this.mvc.perform(post("/login/openid").with(csrf())).andExpect(redirectedUrl("/login?error"));
	}

	@Test
	public void openidLoginWhenAttributeExchangeConfiguredThenFetchAttributesMatchAttributeList() throws Exception {
		OpenIDLoginAttributeExchangeConfig.CONSUMER_MANAGER = mock(ConsumerManager.class);
		AuthRequest mockAuthRequest = mock(AuthRequest.class);
		DiscoveryInformation mockDiscoveryInformation = mock(DiscoveryInformation.class);
		given(mockAuthRequest.getDestinationUrl(anyBoolean())).willReturn("mockUrl");
		given(OpenIDLoginAttributeExchangeConfig.CONSUMER_MANAGER.associate(any()))
				.willReturn(mockDiscoveryInformation);
		given(OpenIDLoginAttributeExchangeConfig.CONSUMER_MANAGER.authenticate(any(DiscoveryInformation.class), any(),
				any())).willReturn(mockAuthRequest);
		this.spring.register(OpenIDLoginAttributeExchangeConfig.class).autowire();
		try (MockWebServer server = new MockWebServer()) {
			String endpoint = server.url("/").toString();
			server.enqueue(new MockResponse().addHeader(YadisResolver.YADIS_XRDS_LOCATION, endpoint));
			server.enqueue(new MockResponse()
					.setBody(String.format("<XRDS><XRD><Service><URI>%s</URI></Service></XRD></XRDS>", endpoint)));
			MvcResult mvcResult = this.mvc.perform(get("/login/openid")
					.param(OpenIDAuthenticationFilter.DEFAULT_CLAIMED_IDENTITY_FIELD, "https://www.google.com/1"))
					.andExpect(status().isFound()).andReturn();
			Object attributeObject = mvcResult.getRequest().getSession()
					.getAttribute("SPRING_SECURITY_OPEN_ID_ATTRIBUTES_FETCH_LIST");
			assertThat(attributeObject).isInstanceOf(List.class);
			List<OpenIDAttribute> attributeList = (List<OpenIDAttribute>) attributeObject;
			assertThat(attributeList.stream().anyMatch((attribute) -> "firstname".equals(attribute.getName())
					&& "https://axschema.org/namePerson/first".equals(attribute.getType()) && attribute.isRequired()))
							.isTrue();
			assertThat(attributeList.stream().anyMatch((attribute) -> "lastname".equals(attribute.getName())
					&& "https://axschema.org/namePerson/last".equals(attribute.getType()) && attribute.isRequired()))
							.isTrue();
			assertThat(attributeList.stream().anyMatch((attribute) -> "email".equals(attribute.getName())
					&& "https://axschema.org/contact/email".equals(attribute.getType()) && attribute.isRequired()))
							.isTrue();
		}
	}

	@Test
	public void openidLoginWhenUsingCustomEndpointsThenMatchesNamespace() throws Exception {
		this.spring.register(OpenIDLoginCustomConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(redirectedUrl("http://localhost/authentication/login"));
		this.mvc.perform(post("/authentication/login/process").with(csrf()))
				.andExpect(redirectedUrl("/authentication/login?failed"));
	}

	@Test
	public void openidLoginWithCustomHandlersThenBehaviorMatchesNamespace() throws Exception {
		OpenIDAuthenticationToken token = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SUCCESS,
				"identityUrl", "message", Arrays.asList(new OpenIDAttribute("name", "type")));
		OpenIDLoginCustomRefsConfig.AUDS = mock(AuthenticationUserDetailsService.class);
		given(OpenIDLoginCustomRefsConfig.AUDS.loadUserDetails(any(Authentication.class)))
				.willReturn(new User("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")));
		OpenIDLoginCustomRefsConfig.ADS = spy(new WebAuthenticationDetailsSource());
		OpenIDLoginCustomRefsConfig.CONSUMER = mock(OpenIDConsumer.class);
		this.spring.register(OpenIDLoginCustomRefsConfig.class, UserDetailsServiceConfig.class).autowire();
		given(OpenIDLoginCustomRefsConfig.CONSUMER.endConsumption(any(HttpServletRequest.class)))
				.willThrow(new AuthenticationServiceException("boom"));
		this.mvc.perform(post("/login/openid").with(csrf()).param("openid.identity", "identity"))
				.andExpect(redirectedUrl("/custom/failure"));
		reset(OpenIDLoginCustomRefsConfig.CONSUMER);
		given(OpenIDLoginCustomRefsConfig.CONSUMER.endConsumption(any(HttpServletRequest.class))).willReturn(token);
		this.mvc.perform(post("/login/openid").with(csrf()).param("openid.identity", "identity"))
				.andExpect(redirectedUrl("/custom/targetUrl"));
		verify(OpenIDLoginCustomRefsConfig.AUDS).loadUserDetails(any(Authentication.class));
		verify(OpenIDLoginCustomRefsConfig.ADS).buildDetails(any(Object.class));
	}

	@Configuration
	@EnableWebSecurity
	static class OpenIDLoginConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.openidLogin()
					.permitAll();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OpenIDLoginAttributeExchangeConfig extends WebSecurityConfigurerAdapter {

		static ConsumerManager CONSUMER_MANAGER;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.openidLogin()
					.consumerManager(CONSUMER_MANAGER)
					.attributeExchange("https://www.google.com/.*") // attribute-exchange@identifier-match
						.attribute("email") // openid-attribute@name
							.type("https://axschema.org/contact/email") // openid-attribute@type
							.required(true) // openid-attribute@required
							.count(1) // openid-attribute@count
							.and()
						.attribute("firstname")
							.type("https://axschema.org/namePerson/first")
							.required(true)
							.and()
						.attribute("lastname")
							.type("https://axschema.org/namePerson/last")
							.required(true)
							.and()
						.and()
					.attributeExchange(".*yahoo.com.*")
						.attribute("email")
							.type("https://schema.openid.net/contact/email")
							.required(true)
							.and()
						.attribute("fullname")
							.type("https://axschema.org/namePerson")
							.required(true)
							.and()
						.and()
					.permitAll();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OpenIDLoginCustomConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			boolean alwaysUseDefaultSuccess = true;
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.openidLogin()
					.permitAll()
					.loginPage("/authentication/login") // openid-login@login-page
					.failureUrl("/authentication/login?failed") // openid-login@authentication-failure-url
					.loginProcessingUrl("/authentication/login/process") // openid-login@login-processing-url
					.defaultSuccessUrl("/default", alwaysUseDefaultSuccess); // openid-login@default-target-url / openid-login@always-use-default-target
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class OpenIDLoginCustomRefsConfig extends WebSecurityConfigurerAdapter {

		static AuthenticationUserDetailsService AUDS;
		static AuthenticationDetailsSource ADS;
		static OpenIDConsumer CONSUMER;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
			handler.setDefaultTargetUrl("/custom/targetUrl");
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.openidLogin()
					// if using UserDetailsService wrap with new UserDetailsByNameServiceWrapper<OpenIDAuthenticationToken>()
					.authenticationUserDetailsService(AUDS) // openid-login@user-service-ref
					.failureHandler(new SimpleUrlAuthenticationFailureHandler("/custom/failure")) // openid-login@authentication-failure-handler-ref
					.successHandler(handler) // openid-login@authentication-success-handler-ref
					.authenticationDetailsSource(ADS) // openid-login@authentication-details-source-ref
					.withObjectPostProcessor(new ObjectPostProcessor<OpenIDAuthenticationFilter>() {
						@Override
						public <O extends OpenIDAuthenticationFilter> O postProcess(O filter) {
							filter.setConsumer(CONSUMER);
							return filter;
						}
					});
			// @formatter:on
		}

	}

	@Configuration
	static class UserDetailsServiceConfig {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
					User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build());
		}

	}

}
