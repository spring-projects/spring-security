/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers.oauth2.client

import org.springframework.context.annotation.Bean
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter

/**
 * test for OAuth2LoginConfigurer.
 * @author Kazuki Shimizu
 */
class OAuth2LoginConfigurerTests extends BaseSpringSpec {

	def "oauth2Login default"() {
		when:
			loadConfig(DefaultOAuth2LoginConfig)
		then:
			OAuth2LoginAuthenticationProvider oauth2Provider = (OAuth2LoginAuthenticationProvider) getOAuth2AuthenticationProvider(1)
			oauth2Provider.authoritiesMapper.mapAuthorities(new ArrayList<>()).size() == 0
		and:
			OidcAuthorizationCodeAuthenticationProvider oidcProvider = (OidcAuthorizationCodeAuthenticationProvider) getOAuth2AuthenticationProvider(2)
			oidcProvider.authoritiesMapper.mapAuthorities(new ArrayList<>()).size() == 0
	}

	def "oauth2Login customize using configurer method"() {
		when:
			loadConfig(CustomUsingConfigurerMethodOAuth2LoginConfig)
		then:
			OAuth2LoginAuthenticationProvider oauth2Provider = (OAuth2LoginAuthenticationProvider) getOAuth2AuthenticationProvider(1)
			oauth2Provider.authoritiesMapper.mapAuthorities(new ArrayList<>()).size() == 1
		and:
			OidcAuthorizationCodeAuthenticationProvider oidcProvider = (OidcAuthorizationCodeAuthenticationProvider) getOAuth2AuthenticationProvider(2)
			oidcProvider.authoritiesMapper.mapAuthorities(new ArrayList<>()).size() == 1
	}

	def "oauth2Login customize using @Bean"() {
		when:
			loadConfig(CustomUsingAtBeanOAuth2LoginConfig)
		then:
			OAuth2LoginAuthenticationProvider oauth2Provider = (OAuth2LoginAuthenticationProvider) getOAuth2AuthenticationProvider(1)
			oauth2Provider.authoritiesMapper.mapAuthorities(new ArrayList<>()).size() == 2
		and:
			OidcAuthorizationCodeAuthenticationProvider oidcProvider = (OidcAuthorizationCodeAuthenticationProvider) getOAuth2AuthenticationProvider(2)
			oidcProvider.authoritiesMapper.mapAuthorities(new ArrayList<>()).size() == 2
	}

	@EnableWebSecurity
	static class DefaultOAuth2LoginConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.oauth2Login()
				.clientRegistrationRepository(new InMemoryClientRegistrationRepository(
					CommonOAuth2Provider.GOOGLE.getBuilder("google")
							.clientId("clientId")
							.clientSecret("clientSecret")
							.build()))
		}

	}

	@EnableWebSecurity
	static class CustomUsingConfigurerMethodOAuth2LoginConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.oauth2Login()
				.clientRegistrationRepository(new InMemoryClientRegistrationRepository(
					CommonOAuth2Provider.GOOGLE.getBuilder("google")
							.clientId("clientId")
							.clientSecret("clientSecret")
							.build()))
				.userInfoEndpoint()
					.userAuthoritiesMapper(new GrantedAuthoritiesMapper() {
						@Override
						Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
							AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER")
						}
					})
		}

	}

	@EnableWebSecurity
	static class CustomUsingAtBeanOAuth2LoginConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.oauth2Login()
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			new InMemoryClientRegistrationRepository(
					CommonOAuth2Provider.GOOGLE.getBuilder("google")
							.clientId("clientId")
							.clientSecret("clientSecret")
							.build())
		}

		@Bean
		GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
			new GrantedAuthoritiesMapper() {
				@Override
				Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
					AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER,ROLE_ADMIN")
				}
			}
		}

	}

	def getOAuth2AuthenticationProvider(int index = 0) {
		((ProviderManager) ((OAuth2LoginAuthenticationFilter) findFilter(OAuth2LoginAuthenticationFilter)).authenticationManager).providers[index]
	}

}