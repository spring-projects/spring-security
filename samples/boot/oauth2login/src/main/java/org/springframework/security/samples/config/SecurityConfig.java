/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.samples.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.config.annotation.web.configurers.OAuth2LoginSecurityConfigurer;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationProperties;
import org.springframework.security.samples.userdetails.GitHubOAuth2UserDetails;

import static org.springframework.security.oauth2.client.config.annotation.web.configurers.OAuth2LoginSecurityConfigurer.oauth2Login;

/**
 * @author Joe Grandja
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired(required = false)
	@Qualifier("githubClientRegistration")
	private ClientRegistration githubClientRegistration;

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		OAuth2LoginSecurityConfigurer<HttpSecurity> oauth2LoginConfigurer = oauth2Login();
		if (this.githubClientRegistration != null) {
			oauth2LoginConfigurer
				.userInfoEndpoint()
					.userInfoTypeMapping(GitHubOAuth2UserDetails.class,
						this.githubClientRegistration.getProviderDetails().getUserInfoUri());
		}

		http
			.authorizeRequests()
				.anyRequest().authenticated()
				.and()
			.apply(oauth2LoginConfigurer);
	}
	// @formatter:on

	@Configuration
	@Profile("google-login")
	static class GoogleClientConfig {

		@ConfigurationProperties(prefix = "security.oauth2.client.google")
		@Bean
		ClientRegistrationProperties googleClientRegistrationProperties() {
			return new ClientRegistrationProperties();
		}

		@Bean
		ClientRegistration googleClientRegistration() {
			return new ClientRegistration.Builder(this.googleClientRegistrationProperties()).build();
		}
	}

	@Configuration
	@Profile("github-login")
	static class GitHubClientConfig {

		@ConfigurationProperties(prefix = "security.oauth2.client.github")
		@Bean
		ClientRegistrationProperties githubClientRegistrationProperties() {
			return new ClientRegistrationProperties();
		}

		@Bean
		ClientRegistration githubClientRegistration() {
			return new ClientRegistration.Builder(this.githubClientRegistrationProperties()).build();
		}
	}

	@Configuration
	@Profile("facebook-login")
	static class FacebookClientConfig {

		@ConfigurationProperties(prefix = "security.oauth2.client.facebook")
		@Bean
		ClientRegistrationProperties facebookClientRegistrationProperties() {
			return new ClientRegistrationProperties();
		}

		@Bean
		ClientRegistration facebookClientRegistration() {
			return new ClientRegistration.Builder(this.facebookClientRegistrationProperties()).build();
		}
	}
}
