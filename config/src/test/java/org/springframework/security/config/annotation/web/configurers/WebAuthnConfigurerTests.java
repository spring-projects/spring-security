/*
 * Copyright 2004-present the original author or authors.
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

import java.nio.charset.StandardCharsets;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.ObservationTextPublisher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationObservationContext;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.observation.SecurityObservationSettings;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ui.DefaultResourcesFilter;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.TestCredentialRecords;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialUserEntities;
import org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsRepository;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;
import org.springframework.security.web.webauthn.management.MapPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.MapUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.security.web.webauthn.registration.HttpSessionPublicKeyCredentialCreationOptionsRepository;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Daniel Garnier-Moiroux
 */
@ExtendWith(SpringTestContextExtension.class)
public class WebAuthnConfigurerTests {

	private static final String REQUEST_OPTIONS_ATTR_NAME = PublicKeyCredentialRequestOptionsRepository.class.getName()
		.concat(".ATTR_NAME");

	private static final String ASSERTION_BODY = """
			{
				"id": "dYF7EGnRFFIXkpXi9XU2wg",
				"rawId": "dYF7EGnRFFIXkpXi9XU2wg",
				"response": {
					"authenticatorData": "y9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNgdAAAAAA",
					"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRFVsRzRDbU9naWhKMG1vdXZFcE9HdUk0ZVJ6MGRRWmxUQmFtbjdHQ1FTNCIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
					"signature": "MEYCIQCW2BcUkRCAXDmGxwMi78jknenZ7_amWrUJEYoTkweldAIhAMD0EMp1rw2GfwhdrsFIeDsL7tfOXVPwOtfqJntjAo4z",
					"userHandle": "Q3_0Xd64_HW0BlKRAJnVagJTpLKLgARCj8zjugpRnVo"
				},
				"clientExtensionResults": {},
				"authenticatorAttachment": "platform"
			}
			""";

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void webauthnWhenConfiguredConfiguredThenServesJavascript() throws Exception {
		this.spring.register(DefaultWebauthnConfiguration.class).autowire();
		this.mvc.perform(get("/login/webauthn.js"))
			.andExpect(status().isOk())
			.andExpect(header().string("content-type", "text/javascript;charset=UTF-8"))
			.andExpect(content().string(containsString("async function authenticate(")));
	}

	@Test
	public void webauthnWhenConfiguredConfiguredThenServesCss() throws Exception {
		this.spring.register(DefaultWebauthnConfiguration.class).autowire();
		this.mvc.perform(get("/default-ui.css"))
			.andExpect(status().isOk())
			.andExpect(header().string("content-type", "text/css;charset=UTF-8"))
			.andExpect(content().string(containsString("body {")));
	}

	// gh-18128
	@Test
	public void webAuthnAuthenticationFilterIsPostProcessed() throws Exception {
		this.spring.register(DefaultWebauthnConfiguration.class, PostProcessorConfiguration.class).autowire();
		PostProcessorConfiguration postProcess = this.spring.getContext().getBean(PostProcessorConfiguration.class);
		assertThat(postProcess.webauthnFilter).isNotNull();
	}

	@Test
	public void webauthnWhenNoFormLoginAndDefaultRegistrationPageConfiguredThenServesJavascript() throws Exception {
		this.spring.register(NoFormLoginAndDefaultRegistrationPageConfiguration.class).autowire();
		this.mvc.perform(get("/login/webauthn.js"))
			.andExpect(status().isOk())
			.andExpect(header().string("content-type", "text/javascript;charset=UTF-8"))
			.andExpect(content().string(containsString("async function authenticate(")));
	}

	@Test
	public void webauthnWhenNoFormLoginAndDefaultRegistrationPageConfiguredThenServesCss() throws Exception {
		this.spring.register(NoFormLoginAndDefaultRegistrationPageConfiguration.class).autowire();
		this.mvc.perform(get("/default-ui.css"))
			.andExpect(status().isOk())
			.andExpect(header().string("content-type", "text/css;charset=UTF-8"))
			.andExpect(content().string(containsString("body {")));
	}

	@Test
	public void webauthnWhenFormLoginAndDefaultRegistrationPageConfiguredThenNoDuplicateFilters() {
		this.spring.register(DefaultWebauthnConfiguration.class).autowire();
		FilterChainProxy filterChain = this.spring.getContext().getBean(FilterChainProxy.class);

		List<DefaultResourcesFilter> defaultResourcesFilters = filterChain.getFilterChains()
			.get(0)
			.getFilters()
			.stream()
			.filter(DefaultResourcesFilter.class::isInstance)
			.map(DefaultResourcesFilter.class::cast)
			.toList();

		assertThat(defaultResourcesFilters).map(DefaultResourcesFilter::toString)
			.filteredOn((filterDescription) -> filterDescription.contains("login/webauthn.js"))
			.hasSize(1);
		assertThat(defaultResourcesFilters).map(DefaultResourcesFilter::toString)
			.filteredOn((filterDescription) -> filterDescription.contains("default-ui.css"))
			.hasSize(1);
	}

	@Test
	void webauthnWhenConfiguredDefaultsRpNameToRpId() throws Exception {
		ObjectMapper mapper = new ObjectMapper();
		this.spring.register(DefaultWebauthnConfiguration.class).autowire();
		String response = this.mvc
			.perform(post("/webauthn/register/options").with(csrf())
				.with(authentication(new TestingAuthenticationToken("test", "ignored", "ROLE_user"))))
			.andExpect(status().is2xxSuccessful())
			.andReturn()
			.getResponse()
			.getContentAsString();

		JsonNode parsedResponse = mapper.readTree(response);

		assertThat(parsedResponse.get("rp").get("id").asText()).isEqualTo("example.com");
		assertThat(parsedResponse.get("rp").get("name").asText()).isEqualTo("example.com");
	}

	@Test
	void webauthnWhenRpNameConfiguredUsesRpName() throws Exception {
		ObjectMapper mapper = new ObjectMapper();
		this.spring.register(CustomRpNameWebauthnConfiguration.class).autowire();
		String response = this.mvc
			.perform(post("/webauthn/register/options").with(csrf())
				.with(authentication(new TestingAuthenticationToken("test", "ignored", "ROLE_user"))))
			.andExpect(status().is2xxSuccessful())
			.andReturn()
			.getResponse()
			.getContentAsString();

		JsonNode parsedResponse = mapper.readTree(response);

		assertThat(parsedResponse.get("rp").get("id").asText()).isEqualTo("example.com");
		assertThat(parsedResponse.get("rp").get("name").asText()).isEqualTo("Test RP Name");
	}

	@Test
	public void webauthnWhenConfiguredAndFormLoginThenDoesServesJavascript() throws Exception {
		this.spring.register(FormLoginAndNoDefaultRegistrationPageConfiguration.class).autowire();
		this.mvc.perform(get("/login/webauthn.js"))
			.andExpect(status().isOk())
			.andExpect(header().string("content-type", "text/javascript;charset=UTF-8"))
			.andExpect(content().string(containsString("async function authenticate(")));
	}

	@Test
	public void webauthnWhenConfiguredAndNoDefaultRegistrationPageThenDoesNotServeJavascript() throws Exception {
		this.spring.register(NoDefaultRegistrationPageConfiguration.class).autowire();
		this.mvc.perform(get("/login/webauthn.js")).andExpect(status().isNotFound());
	}

	@Test
	public void webauthnWhenConfiguredPublicKeyCredentialCreationOptionsRepository() throws Exception {
		TestingAuthenticationToken user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolder.setContext(new SecurityContextImpl(user));
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		WebAuthnRelyingPartyOperations rpOperations = mock(WebAuthnRelyingPartyOperations.class);
		ConfigCredentialCreationOptionsRepository.rpOperations = rpOperations;
		given(rpOperations.createPublicKeyCredentialCreationOptions(any())).willReturn(options);
		String attrName = "attrName";
		HttpSessionPublicKeyCredentialCreationOptionsRepository creationOptionsRepository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();
		creationOptionsRepository.setAttrName(attrName);
		ConfigCredentialCreationOptionsRepository.creationOptionsRepository = creationOptionsRepository;
		this.spring.register(ConfigCredentialCreationOptionsRepository.class).autowire();
		this.mvc.perform(post("/webauthn/register/options"))
			.andExpect(status().isOk())
			.andExpect(request().sessionAttribute(attrName, options));
	}

	@Test
	public void webauthnWhenConfiguredPublicKeyCredentialCreationOptionsRepositoryBeanPresent() throws Exception {
		TestingAuthenticationToken user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolder.setContext(new SecurityContextImpl(user));
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		WebAuthnRelyingPartyOperations rpOperations = mock(WebAuthnRelyingPartyOperations.class);
		ConfigCredentialCreationOptionsRepositoryFromBean.rpOperations = rpOperations;
		given(rpOperations.createPublicKeyCredentialCreationOptions(any())).willReturn(options);
		String attrName = "attrName";
		HttpSessionPublicKeyCredentialCreationOptionsRepository creationOptionsRepository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();
		creationOptionsRepository.setAttrName(attrName);
		ConfigCredentialCreationOptionsRepositoryFromBean.creationOptionsRepository = creationOptionsRepository;
		this.spring.register(ConfigCredentialCreationOptionsRepositoryFromBean.class).autowire();
		this.mvc.perform(post("/webauthn/register/options"))
			.andExpect(status().isOk())
			.andExpect(request().sessionAttribute(attrName, options));
	}

	@Test
	public void webauthnWhenConfiguredMessageConverter() throws Exception {
		TestingAuthenticationToken user = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolder.setContext(new SecurityContextImpl(user));
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		WebAuthnRelyingPartyOperations rpOperations = mock(WebAuthnRelyingPartyOperations.class);
		ConfigMessageConverter.rpOperations = rpOperations;
		given(rpOperations.createPublicKeyCredentialCreationOptions(any())).willReturn(options);
		HttpMessageConverter<Object> converter = mock(HttpMessageConverter.class);
		given(converter.canWrite(any(), any())).willReturn(true);
		String expectedBody = "123";
		willAnswer((args) -> {
			HttpOutputMessage out = (HttpOutputMessage) args.getArguments()[2];
			out.getBody().write(expectedBody.getBytes(StandardCharsets.UTF_8));
			return null;
		}).given(converter).write(any(), any(), any());
		ConfigMessageConverter.converter = converter;
		this.spring.register(ConfigMessageConverter.class).autowire();
		this.mvc.perform(post("/webauthn/register/options"))
			.andExpect(status().isOk())
			.andExpect(content().string(expectedBody));
	}

	@Test
	void webauthnWhenDeleteAndCredentialBelongsToUserThenNoContent() throws Exception {
		this.spring.register(DeleteCredentialConfiguration.class).autowire();
		this.mvc
			.perform(delete("/webauthn/register/" + DeleteCredentialConfiguration.CREDENTIAL_ID_BASE64URL)
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
			.andExpect(status().isNoContent());
	}

	@Test
	void webauthnWhenDeleteAndCredentialBelongsToDifferentUserThenForbidden() throws Exception {
		this.spring.register(DeleteCredentialConfiguration.class).autowire();
		this.mvc
			.perform(delete("/webauthn/register/" + DeleteCredentialConfiguration.CREDENTIAL_ID_BASE64URL)
				.with(authentication(new TestingAuthenticationToken("other-user", "password", "ROLE_USER"))))
			.andExpect(status().isForbidden());
	}

	@Test
	public void webauthnWhenAuthenticationEventPublisherBeanThenUsed() {
		this.spring.register(DefaultWebauthnConfiguration.class, CustomEventPublisherConfig.class).autowire();

		FilterChainProxy filterChain = this.spring.getContext().getBean(FilterChainProxy.class);
		WebAuthnAuthenticationFilter webAuthnFilter = filterChain.getFilterChains()
			.get(0)
			.getFilters()
			.stream()
			.filter(WebAuthnAuthenticationFilter.class::isInstance)
			.map(WebAuthnAuthenticationFilter.class::cast)
			.findFirst()
			.orElseThrow();

		AuthenticationManager authManager = (AuthenticationManager) ReflectionTestUtils.getField(webAuthnFilter,
				"authenticationManager");
		assertThat(authManager).isInstanceOf(ProviderManager.class);

		Object publisher = ReflectionTestUtils.getField(authManager, "eventPublisher");
		AuthenticationEventPublisher expectedPublisher = this.spring.getContext()
			.getBean(AuthenticationEventPublisher.class);
		assertThat(publisher).isSameAs(expectedPublisher);
	}

	@Test
	public void webauthnWhenNoAuthenticationEventPublisherBeanThenDefaultNullPublisher() {
		this.spring.register(DefaultWebauthnConfiguration.class).autowire();

		FilterChainProxy filterChain = this.spring.getContext().getBean(FilterChainProxy.class);
		WebAuthnAuthenticationFilter webAuthnFilter = filterChain.getFilterChains()
			.get(0)
			.getFilters()
			.stream()
			.filter(WebAuthnAuthenticationFilter.class::isInstance)
			.map(WebAuthnAuthenticationFilter.class::cast)
			.findFirst()
			.orElseThrow();

		AuthenticationManager authManager = (AuthenticationManager) ReflectionTestUtils.getField(webAuthnFilter,
				"authenticationManager");
		assertThat(authManager).isInstanceOf(ProviderManager.class);

		Object publisher = ReflectionTestUtils.getField(authManager, "eventPublisher");
		// ProviderManager.java:316: private static final class NullEventPublisher
		assertThat(publisher).isNotNull();
		assertThat(publisher.getClass().getDeclaringClass()).isEqualTo(ProviderManager.class);
		assertThat(publisher.getClass().getName()).contains("NullEventPublisher");
	}

	@Test
	public void webauthnWhenObservationRegistryThenObservesAuthentication() throws Exception {
		this.spring.register(WebAuthnLoginConfiguration.class, ObservationRegistryConfig.class).autowire();
		WebAuthnRelyingPartyOperations rpOperations = this.spring.getContext()
			.getBean(WebAuthnRelyingPartyOperations.class);
		given(rpOperations.authenticate(any()))
			.willReturn(TestPublicKeyCredentialUserEntities.userEntity().name("user").build());
		ObservationHandler<Observation.Context> handler = this.spring.getContext().getBean(ObservationHandler.class);
		this.mvc.perform(webAuthnLogin()).andExpect(status().isOk());
		ArgumentCaptor<Observation.Context> context = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, atLeastOnce()).onStart(context.capture());
		assertThat(context.getAllValues()).anyMatch(AuthenticationObservationContext.class::isInstance);
		verify(handler, atLeastOnce()).onStop(context.capture());
		assertThat(context.getAllValues()).anyMatch(AuthenticationObservationContext.class::isInstance);
		given(rpOperations.authenticate(any())).willThrow(new IllegalArgumentException("invalid assertion"));
		this.mvc.perform(webAuthnLogin()).andExpect(status().isUnauthorized());
		verify(handler).onError(context.capture());
		assertThat(context.getValue()).isInstanceOf(AuthenticationObservationContext.class);
	}

	@Test
	public void webauthnWhenExcludeAuthenticationObservationsThenUnobserved() throws Exception {
		this.spring
			.register(WebAuthnLoginConfiguration.class, ObservationRegistryConfig.class,
					SelectableObservationsConfig.class)
			.autowire();
		WebAuthnRelyingPartyOperations rpOperations = this.spring.getContext()
			.getBean(WebAuthnRelyingPartyOperations.class);
		given(rpOperations.authenticate(any()))
			.willReturn(TestPublicKeyCredentialUserEntities.userEntity().name("user").build());
		ObservationHandler<Observation.Context> handler = this.spring.getContext().getBean(ObservationHandler.class);
		this.mvc.perform(webAuthnLogin()).andExpect(status().isOk());
		ArgumentCaptor<Observation.Context> context = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, atLeastOnce()).onStart(context.capture());
		assertThat(context.getAllValues()).noneMatch(AuthenticationObservationContext.class::isInstance);
		context = ArgumentCaptor.forClass(Observation.Context.class);
		verify(handler, atLeastOnce()).onStop(context.capture());
		assertThat(context.getAllValues()).noneMatch(AuthenticationObservationContext.class::isInstance);
		given(rpOperations.authenticate(any())).willThrow(new IllegalArgumentException("invalid assertion"));
		this.mvc.perform(webAuthnLogin()).andExpect(status().isUnauthorized());
		verify(handler, never()).onError(any());
	}

	private static MockHttpServletRequestBuilder webAuthnLogin() {
		return post("/login/webauthn").contentType(MediaType.APPLICATION_JSON)
			.content(ASSERTION_BODY)
			.sessionAttr(REQUEST_OPTIONS_ATTR_NAME, TestPublicKeyCredentialRequestOptions.create().build());
	}

	@Configuration
	@EnableWebSecurity
	static class ConfigCredentialCreationOptionsRepository {

		private static HttpSessionPublicKeyCredentialCreationOptionsRepository creationOptionsRepository;

		private static WebAuthnRelyingPartyOperations rpOperations;

		@Bean
		WebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations() {
			return ConfigCredentialCreationOptionsRepository.rpOperations;
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.csrf(AbstractHttpConfigurer::disable)
				.webAuthn((c) -> c.creationOptionsRepository(creationOptionsRepository))
				.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ConfigCredentialCreationOptionsRepositoryFromBean {

		private static HttpSessionPublicKeyCredentialCreationOptionsRepository creationOptionsRepository;

		private static WebAuthnRelyingPartyOperations rpOperations;

		@Bean
		WebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations() {
			return ConfigCredentialCreationOptionsRepositoryFromBean.rpOperations;
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		HttpSessionPublicKeyCredentialCreationOptionsRepository creationOptionsRepository() {
			return ConfigCredentialCreationOptionsRepositoryFromBean.creationOptionsRepository;
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.csrf(AbstractHttpConfigurer::disable).webAuthn(Customizer.withDefaults()).build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class ConfigMessageConverter {

		private static HttpMessageConverter<Object> converter;

		private static WebAuthnRelyingPartyOperations rpOperations;

		@Bean
		WebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations() {
			return ConfigMessageConverter.rpOperations;
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.csrf(AbstractHttpConfigurer::disable).webAuthn((c) -> c.messageConverter(converter)).build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class CustomEventPublisherConfig {

		@Bean
		AuthenticationEventPublisher authenticationEventPublisher() {
			return mock(AuthenticationEventPublisher.class);
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class PostProcessorConfiguration {

		WebAuthnAuthenticationFilter webauthnFilter;

		@Bean
		BeanPostProcessor beanPostProcessor() {
			return new BeanPostProcessor() {
				@Override
				public Object postProcessAfterInitialization(Object bean, String beanName) {
					if (bean instanceof WebAuthnAuthenticationFilter filter) {
						PostProcessorConfiguration.this.webauthnFilter = filter;
					}
					return bean;
				}
			};
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultWebauthnConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(Customizer.withDefaults())
				.webAuthn((authn) -> authn
					.rpId("example.com")
				);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomRpNameWebauthnConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.formLogin(Customizer.withDefaults())
				.webAuthn((webauthn) -> webauthn.rpId("example.com").rpName("Test RP Name"))
				.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NoFormLoginAndDefaultRegistrationPageConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.webAuthn((authn) -> authn
						.rpId("spring.io")
						.rpName("spring")
				);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class FormLoginAndNoDefaultRegistrationPageConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(Customizer.withDefaults())
				.webAuthn((authn) -> authn
					.rpId("spring.io")
					.rpName("spring")
					.disableDefaultRegistrationPage(true)
				);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NoDefaultRegistrationPageConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.formLogin((login) -> login
						.loginPage("/custom-login-page")
					)
					.webAuthn((authn) -> authn
						.rpId("spring.io")
						.rpName("spring")
						.disableDefaultRegistrationPage(true)
					);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DeleteCredentialConfiguration {

		static final String CREDENTIAL_ID_BASE64URL = "NauGCN7bZ5jEBwThcde51g";

		static final Bytes USER_ENTITY_ID = Bytes.fromBase64("vKBFhsWT3gQnn-gHdT4VXIvjDkVXVYg5w8CLGHPunMM");

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

		@Bean
		WebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations() {
			return mock(WebAuthnRelyingPartyOperations.class);
		}

		@Bean
		UserCredentialRepository userCredentialRepository() {
			MapUserCredentialRepository repository = new MapUserCredentialRepository();
			repository.save(TestCredentialRecords.userCredential().build());
			return repository;
		}

		@Bean
		PublicKeyCredentialUserEntityRepository userEntityRepository() {
			MapPublicKeyCredentialUserEntityRepository repository = new MapPublicKeyCredentialUserEntityRepository();
			repository.save(ImmutablePublicKeyCredentialUserEntity.builder()
				.name("user")
				.id(USER_ENTITY_ID)
				.displayName("User")
				.build());
			return repository;
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.csrf(AbstractHttpConfigurer::disable).webAuthn(Customizer.withDefaults()).build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class WebAuthnLoginConfiguration {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
					User.withUsername("user").password("{noop}password").roles("USER").build());
		}

		@Bean
		WebAuthnRelyingPartyOperations webAuthnRelyingPartyOperations() {
			return mock(WebAuthnRelyingPartyOperations.class);
		}

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			return http.csrf(AbstractHttpConfigurer::disable).webAuthn(Customizer.withDefaults()).build();
		}

	}

	@Configuration
	static class ObservationRegistryConfig {

		private final ObservationRegistry registry = ObservationRegistry.create();

		private final ObservationHandler<Observation.Context> handler = spy(new ObservationTextPublisher());

		@Bean
		ObservationRegistry observationRegistry() {
			return this.registry;
		}

		@Bean
		ObservationHandler<Observation.Context> observationHandler() {
			return this.handler;
		}

		@Bean
		ObservationRegistryPostProcessor observationRegistryPostProcessor(
				ObjectProvider<ObservationHandler<Observation.Context>> handler) {
			return new ObservationRegistryPostProcessor(handler);
		}

	}

	static class ObservationRegistryPostProcessor implements BeanPostProcessor {

		private final ObjectProvider<ObservationHandler<Observation.Context>> handler;

		ObservationRegistryPostProcessor(ObjectProvider<ObservationHandler<Observation.Context>> handler) {
			this.handler = handler;
		}

		@Override
		public Object postProcessAfterInitialization(Object bean, String beanName) {
			if (bean instanceof ObservationRegistry registry) {
				registry.observationConfig().observationHandler(this.handler.getObject());
			}
			return bean;
		}

	}

	@Configuration
	static class SelectableObservationsConfig {

		@Bean
		SecurityObservationSettings observabilityDefaults() {
			return SecurityObservationSettings.withDefaults()
				.shouldObserveRequests(true)
				.shouldObserveAuthentications(false)
				.build();
		}

	}

}
