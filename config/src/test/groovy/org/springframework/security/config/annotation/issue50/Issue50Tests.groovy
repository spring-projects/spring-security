/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.issue50;

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.issue50.domain.User
import org.springframework.security.config.annotation.issue50.repo.UserRepository
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.FilterChainProxy
import org.springframework.test.context.ContextConfiguration
import org.springframework.transaction.annotation.Transactional

import spock.lang.Specification

/**
 * @author Rob Winch
 *
 */
@ContextConfiguration(classes=[ApplicationConfig,SecurityConfig])
@Transactional
class Issue50Tests extends Specification {
	@Autowired
	private FilterChainProxy springSecurityFilterChain
	@Autowired
	private AuthenticationManager authenticationManager
	@Autowired
	private UserRepository userRepo

	def setup() {
		SecurityContextHolder.context.authentication = new TestingAuthenticationToken("test",null,"ROLE_ADMIN")
	}

	def cleanup() {
		SecurityContextHolder.clearContext()
	}

	// https://github.com/SpringSource/spring-security-javaconfig/issues/50
	def "#50 - GlobalMethodSecurityConfiguration should load AuthenticationManager lazily"() {
		when:
		"Configuration Loads"
		then: "GlobalMethodSecurityConfiguration loads AuthenticationManager lazily"
		noExceptionThrown()
	}

	def "AuthenticationManager will not authenticate missing user"() {
		when:
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("test", "password"))
		then:
		thrown(UsernameNotFoundException)
	}

	def "AuthenticationManager will not authenticate with invalid password"() {
		when:
		User user = new User(username:"test",password:"password")
		userRepo.save(user)
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.username , "invalid"))
		then:
		thrown(BadCredentialsException)
	}

	def "AuthenticationManager can be used to authenticate a user"() {
		when:
		User user = new User(username:"test",password:"password")
		userRepo.save(user)
		Authentication result = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.username , user.password))
		then:
		result.principal == user.username
	}

	def "Global Method Security is enabled and works"() {
		setup:
		SecurityContextHolder.context.authentication = new TestingAuthenticationToken("test",null,"ROLE_USER")
		when:
		User user = new User(username:"denied",password:"password")
		userRepo.save(user)
		Authentication result = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.username , user.password))
		then:
		thrown(AccessDeniedException)
	}
}
