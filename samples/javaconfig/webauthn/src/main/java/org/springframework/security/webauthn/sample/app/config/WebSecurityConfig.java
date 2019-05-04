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

package org.springframework.security.webauthn.sample.app.config;

import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.mfa.MultiFactorAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import org.springframework.security.webauthn.config.configurers.WebAuthnAuthenticationProviderConfigurer;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;

import static org.springframework.security.webauthn.config.configurers.WebAuthnLoginConfigurer.webAuthnLogin;


/**
 * Security Configuration
 */
@Configuration
@Import(value = WebSecurityBeanConfig.class)
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private DaoAuthenticationProvider daoAuthenticationProvider;

	@Autowired
	private WebAuthnUserDetailsService userDetailsService;

	@Autowired
	private WebAuthnAuthenticatorService authenticatorService;

	@Autowired
	private WebAuthnAuthenticationContextValidator webAuthnAuthenticationContextValidator;

	@Override
	public void configure(AuthenticationManagerBuilder builder) throws Exception {
		builder.apply(new WebAuthnAuthenticationProviderConfigurer<>(userDetailsService, authenticatorService, webAuthnAuthenticationContextValidator));
		builder.apply(new MultiFactorAuthenticationProviderConfigurer<>(daoAuthenticationProvider));
	}

	@Override
	public void configure(WebSecurity web) {
		// ignore static resources
		web.ignoring().antMatchers(
				"/favicon.ico",
				"/webjars/**",
				"/js/**",
				"/css/**");
	}

	/**
	 * Configure SecurityFilterChain
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		// WebAuthn Login
		http.apply(webAuthnLogin())
				.rpName("Spring Security WebAuthn Sample")
				.attestation(AttestationConveyancePreference.NONE)
				.publicKeyCredParams()
				.addPublicKeyCredParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256)  // Windows Hello
				.addPublicKeyCredParams(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256) // FIDO U2F Key, etc
				.and()
				.loginPage("/login")
				.usernameParameter("username")
				.passwordParameter("password")
				.credentialIdParameter("credentialId")
				.clientDataJSONParameter("clientDataJSON")
				.authenticatorDataParameter("authenticatorData")
				.signatureParameter("signature")
				.clientExtensionsJSONParameter("clientExtensionsJSON")
				.loginProcessingUrl("/login")
				.successHandler(new SimpleUrlAuthenticationSuccessHandler("/dashboard"));

		// Logout
		http.logout()
				.logoutUrl("/logout");
		// Authorization
		http.authorizeRequests()
				.mvcMatchers("/").permitAll()
				.mvcMatchers("/signup").permitAll()
				.mvcMatchers("/login").permitAll()
				.mvcMatchers("/h2-console/**").denyAll()
				.anyRequest().fullyAuthenticated();

		http.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());

	}

}
