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

import javax.security.auth.x500.X500Principal;

import jakarta.servlet.http.HttpServletRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

/**
 * Tests to verify that all the functionality of &lt;x509&gt; attributes is present in
 * Java config
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
@ExtendWith(SpringTestContextExtension.class)
public class NamespaceHttpX509Tests {

	private static final User USER = new User("customuser", "password",
			AuthorityUtils.createAuthorityList("ROLE_USER"));

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void x509AuthenticationWhenUsingX509DefaultConfigurationThenMatchesNamespace() throws Exception {
		this.spring.register(X509Config.class, X509Controller.class).autowire();
		X509Certificate certificate = loadCert("rod.cer");
		this.mvc.perform(get("/whoami").with(x509(certificate))).andExpect(content().string("rod"));
	}

	@Test
	public void x509AuthenticationWhenHasCustomAuthenticationDetailsSourceThenMatchesNamespace() throws Exception {
		this.spring.register(AuthenticationDetailsSourceRefConfig.class, X509Controller.class).autowire();
		X509Certificate certificate = loadCert("rod.cer");
		this.mvc.perform(get("/whoami").with(x509(certificate))).andExpect(content().string("rod"));
		verifyBean(AuthenticationDetailsSource.class).buildDetails(any());
	}

	@Test
	public void x509AuthenticationWhenHasSubjectPrincipalRegexThenMatchesNamespace() throws Exception {
		this.spring.register(SubjectPrincipalRegexConfig.class, X509Controller.class).autowire();
		X509Certificate certificate = loadCert("rodatexampledotcom.cer");
		this.mvc.perform(get("/whoami").with(x509(certificate))).andExpect(content().string("rod"));
	}

	@Test
	public void x509AuthenticationWhenHasCustomPrincipalExtractorThenMatchesNamespace() throws Exception {
		this.spring.register(CustomPrincipalExtractorConfig.class, X509Controller.class).autowire();
		X509Certificate certificate = loadCert("rodatexampledotcom.cer");
		this.mvc.perform(get("/whoami").with(x509(certificate))).andExpect(content().string("rod@example.com"));
	}

	@Test
	public void x509AuthenticationWhenHasCustomUserDetailsServiceThenMatchesNamespace() throws Exception {
		this.spring.register(UserDetailsServiceRefConfig.class, X509Controller.class).autowire();
		X509Certificate certificate = loadCert("rodatexampledotcom.cer");
		this.mvc.perform(get("/whoami").with(x509(certificate))).andExpect(content().string("customuser"));
	}

	@Test
	public void x509AuthenticationWhenHasCustomAuthenticationUserDetailsServiceThenMatchesNamespace() throws Exception {
		this.spring.register(AuthenticationUserDetailsServiceConfig.class, X509Controller.class).autowire();
		X509Certificate certificate = loadCert("rodatexampledotcom.cer");
		this.mvc.perform(get("/whoami").with(x509(certificate))).andExpect(content().string("customuser"));
	}

	<T extends Certificate> T loadCert(String location) {
		try (InputStream is = new ClassPathResource(location).getInputStream()) {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			return (T) certFactory.generateCertificate(is);
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}

	<T> T verifyBean(Class<T> beanClass) {
		return verify(this.spring.getContext().getBean(beanClass));
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	public static class X509Config {

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("rod").password("password")
					.roles("USER", "ADMIN").build();
			return new InMemoryUserDetailsManager(user);
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.x509();
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class AuthenticationDetailsSourceRefConfig {

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("rod").password("password")
					.roles("USER", "ADMIN").build();
			return new InMemoryUserDetailsManager(user);
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.x509()
					.authenticationDetailsSource(authenticationDetailsSource());
			// @formatter:on
			return http.build();
		}

		@Bean
		AuthenticationDetailsSource<HttpServletRequest, PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails> authenticationDetailsSource() {
			return mock(AuthenticationDetailsSource.class);
		}

	}

	@EnableWebMvc
	@Configuration
	@EnableWebSecurity
	public static class SubjectPrincipalRegexConfig {

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("rod").password("password")
					.roles("USER", "ADMIN").build();
			return new InMemoryUserDetailsManager(user);
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.x509()
					.subjectPrincipalRegex("CN=(.*?)@example.com(?:,|$)");
			// @formatter:on
			return http.build();
		}

	}

	@EnableWebMvc
	@Configuration
	@EnableWebSecurity
	public static class CustomPrincipalExtractorConfig {

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("rod@example.com").password("password")
					.roles("USER", "ADMIN").build();
			return new InMemoryUserDetailsManager(user);
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.x509()
					.x509PrincipalExtractor(this::extractCommonName);
			// @formatter:on
			return http.build();
		}

		private String extractCommonName(X509Certificate certificate) {
			X500Principal principal = certificate.getSubjectX500Principal();
			return new X500Name(principal.getName()).getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
		}

	}

	@EnableWebMvc
	@Configuration
	@EnableWebSecurity
	public static class UserDetailsServiceRefConfig {

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("rod").password("password")
					.roles("USER", "ADMIN").build();
			return new InMemoryUserDetailsManager(user);
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.x509()
					.userDetailsService((username) -> USER);
			// @formatter:on
			return http.build();
		}

	}

	@EnableWebMvc
	@Configuration
	@EnableWebSecurity
	public static class AuthenticationUserDetailsServiceConfig {

		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("rod").password("password")
					.roles("USER", "ADMIN").build();
			return new InMemoryUserDetailsManager(user);
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.x509()
					.authenticationUserDetailsService((authentication) -> USER);
			// @formatter:on
			return http.build();
		}

	}

	@RestController
	public static class X509Controller {

		@GetMapping("/whoami")
		public String whoami(@AuthenticationPrincipal(expression = "username") String name) {
			return name;
		}

	}

}
