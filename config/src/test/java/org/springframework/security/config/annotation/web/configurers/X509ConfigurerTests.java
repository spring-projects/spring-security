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

package org.springframework.security.config.annotation.web.configurers;

import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityContextChangedListenerConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.context.SecurityContextChangedListener;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.annotation.SecurityContextChangedListenerArgumentMatchers.setAuthentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Tests for {@link X509Configurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension.class)
public class X509ConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnX509AuthenticationFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(X509AuthenticationFilter.class));
	}

	@Test
	public void x509WhenInvokedTwiceThenUsesOriginalSubjectPrincipalRegex() throws Exception {
		this.spring.register(DuplicateDoesNotOverrideConfig.class).autowire();
		X509Certificate certificate = loadCert("rodatexampledotcom.cer");
		// @formatter:off
		this.mvc.perform(get("/").with(x509(certificate)))
				.andExpect(authenticated().withUsername("rod"));
		// @formatter:on
	}

	@Test
	public void x509WhenConfiguredInLambdaThenUsesDefaults() throws Exception {
		this.spring.register(DefaultsInLambdaConfig.class).autowire();
		X509Certificate certificate = loadCert("rod.cer");
		// @formatter:off
		this.mvc.perform(get("/").with(x509(certificate)))
				.andExpect(authenticated().withUsername("rod"));
		// @formatter:on
	}

	@Test
	public void x509WhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		this.spring.register(DefaultsInLambdaConfig.class, SecurityContextChangedListenerConfig.class).autowire();
		X509Certificate certificate = loadCert("rod.cer");
		// @formatter:off
		this.mvc.perform(get("/").with(x509(certificate)))
				.andExpect(authenticated().withUsername("rod"));
		// @formatter:on
		SecurityContextHolderStrategy strategy = this.spring.getContext().getBean(SecurityContextHolderStrategy.class);
		verify(strategy, atLeastOnce()).getContext();
		SecurityContextChangedListener listener = this.spring.getContext()
				.getBean(SecurityContextChangedListener.class);
		verify(listener).securityContextChanged(setAuthentication(PreAuthenticatedAuthenticationToken.class));
	}

	@Test
	public void x509WhenSubjectPrincipalRegexInLambdaThenUsesRegexToExtractPrincipal() throws Exception {
		this.spring.register(SubjectPrincipalRegexInLambdaConfig.class).autowire();
		X509Certificate certificate = loadCert("rodatexampledotcom.cer");
		// @formatter:off
		this.mvc.perform(get("/").with(x509(certificate)))
				.andExpect(authenticated().withUsername("rod"));
		// @formatter:on
	}

	@Test
	public void x509WhenUserDetailsServiceNotConfiguredThenUsesBean() throws Exception {
		this.spring.register(UserDetailsServiceBeanConfig.class).autowire();
		X509Certificate certificate = loadCert("rod.cer");
		// @formatter:off
		this.mvc.perform(get("/").with(x509(certificate)))
				.andExpect(authenticated().withUsername("rod"));
		// @formatter:on
	}

	@Test
	public void x509WhenUserDetailsServiceAndBeanConfiguredThenDoesNotUseBean() throws Exception {
		this.spring.register(UserDetailsServiceAndBeanConfig.class).autowire();
		X509Certificate certificate = loadCert("rod.cer");
		// @formatter:off
		this.mvc.perform(get("/").with(x509(certificate)))
				.andExpect(authenticated().withUsername("rod"));
		// @formatter:on
	}

	private <T extends Certificate> T loadCert(String location) {
		try (InputStream is = new ClassPathResource(location).getInputStream()) {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			return (T) certFactory.generateCertificate(is);
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}

	@Configuration
	@EnableWebSecurity
	static class ObjectPostProcessorConfig {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.x509();
			return http.build();
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

	@Configuration
	@EnableWebSecurity
	static class DuplicateDoesNotOverrideConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.x509()
					.subjectPrincipalRegex("CN=(.*?)@example.com(?:,|$)")
					.and()
				.x509();
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("rod").password("password")
					.roles("USER", "ADMIN").build();
			return new InMemoryUserDetailsManager(user);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultsInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.x509(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("rod").password("password")
					.roles("USER", "ADMIN").build();
			return new InMemoryUserDetailsManager(user);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SubjectPrincipalRegexInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.x509((x509) ->
					x509
						.subjectPrincipalRegex("CN=(.*?)@example.com(?:,|$)")
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("rod").password("password")
					.roles("USER", "ADMIN").build();
			return new InMemoryUserDetailsManager(user);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class UserDetailsServiceBeanConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.x509(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			// @formatter:off
			return new InMemoryUserDetailsManager(
					User.withDefaultPasswordEncoder()
							.username("rod")
							.password("password")
							.roles("USER", "ADMIN")
							.build()
			);
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class UserDetailsServiceAndBeanConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			UserDetailsService customUserDetailsService = new InMemoryUserDetailsManager(
					User.withDefaultPasswordEncoder()
							.username("rod")
							.password("password")
							.roles("USER", "ADMIN")
							.build());
			http
				.x509((x509) -> x509
					.userDetailsService(customUserDetailsService)
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			// @formatter:off
			return mock(UserDetailsService.class);
		}

	}

}
