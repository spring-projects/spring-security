/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.authentication

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationEventPublisher
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 *
 * @author Rob Winch
 *
 */
class AuthenticationManagerBuilderTests extends BaseSpringSpec {
	def "add(AuthenticationProvider) does not perform registration"() {
		setup:
			ObjectPostProcessor opp = Mock()
			AuthenticationProvider provider = Mock()
			AuthenticationManagerBuilder builder = new AuthenticationManagerBuilder(objectPostProcessor).objectPostProcessor(opp)
		when: "Adding an AuthenticationProvider"
			builder.authenticationProvider(provider)
			builder.build()
		then: "AuthenticationProvider is not passed into LifecycleManager (it should be managed externally)"
			0 * opp._(_ as AuthenticationProvider)
	}

	// https://github.com/SpringSource/spring-security-javaconfig/issues/132
	def "#132 Custom AuthenticationEventPublisher with Web configure(AuthenticationManagerBuilder)"() {
		setup:
			AuthenticationEventPublisher aep = Mock()
		when:
			AuthenticationManager am = new AuthenticationManagerBuilder(objectPostProcessor)
				.authenticationEventPublisher(aep)
				.inMemoryAuthentication()
					.and()
				.build()
		then:
			am.eventPublisher == aep
	}

	def "authentication-manager support multiple DaoAuthenticationProvider's"() {
		setup:
			loadConfig(MultiAuthenticationProvidersConfig)
		when:
			Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("user","password"))
		then:
			auth.name == "user"
			auth.authorities*.authority == ['ROLE_USER']
		when:
			auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("admin","password"))
		then:
			auth.name == "admin"
			auth.authorities*.authority.sort() == ['ROLE_ADMIN','ROLE_USER']
	}

	@EnableWebSecurity
	static class MultiAuthenticationProvidersConfig extends WebSecurityConfigurerAdapter {
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER").and()
					.and()
				.inMemoryAuthentication()
					.withUser("admin").password("password").roles("USER","ADMIN")
		}
	}

	def "isConfigured with AuthenticationProvider"() {
		setup:
			ObjectPostProcessor opp = Mock()
			AuthenticationProvider provider = Mock()
			AuthenticationManagerBuilder auth = new AuthenticationManagerBuilder(opp)
		when:
			auth
				.authenticationProvider(provider)
		then:
			auth.isConfigured()
	}

	def "isConfigured with parent"() {
		setup:
			ObjectPostProcessor opp = Mock()
			AuthenticationManager parent = Mock()
			AuthenticationManagerBuilder auth = new AuthenticationManagerBuilder(opp)
		when:
			auth
				.parentAuthenticationManager(parent)
		then:
			auth.isConfigured()
	}

	def "isConfigured not configured"() {
		setup:
			ObjectPostProcessor opp = Mock()
		when:
			AuthenticationManagerBuilder auth = new AuthenticationManagerBuilder(opp)
		then:
			auth.isConfigured() == false
	}

	def "user from properties"() {
		setup:
		loadConfig(UserFromPropertiesConfig)
		AuthenticationManager manager = context.getBean(AuthenticationConfiguration).authenticationManager
		when:
		manager.authenticate(new UsernamePasswordAuthenticationToken("joe","joespassword"))
		then:
		noExceptionThrown()
	}

	@Configuration
	@EnableGlobalAuthentication
	@Import(ObjectPostProcessorConfiguration.class)
	static class UserFromPropertiesConfig {

		@Value("classpath:org/springframework/security/config/users.properties")
		Resource users;

		@Bean
		public AuthenticationManager authenticationManager() {
			return new ProviderManager(Arrays.asList(authenticationProvider()));
		}

		@Bean
		public AuthenticationProvider authenticationProvider() {
			DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
			provider.setUserDetailsService(userDetailsService())
			return provider;
		}

		@Bean
		public UserDetailsService userDetailsService() {
			Properties properties = new Properties();
			properties.load(users.getInputStream());
			return new InMemoryUserDetailsManager(properties);
		}
	}
}
