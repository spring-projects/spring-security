/*
 * Copyright 2002-2016 the original author or authors.
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

import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.BaseSpringSpec

import static org.springframework.security.config.annotation.authentication.PasswordEncoderConfigurerConfigs.PasswordEncoderConfig
import static org.springframework.security.config.annotation.authentication.PasswordEncoderConfigurerConfigs.PasswordEncoderNoAuthManagerLoadsConfig;

/**
 *
 * @author Rob Winch
 *
 */
class PasswordEncoderConfigurerTests extends BaseSpringSpec {
	def "password-encoder@ref with No AuthenticationManager Bean"() {
		when:
			loadConfig(PasswordEncoderNoAuthManagerLoadsConfig)
		then:
			noExceptionThrown()
	}

	def "password-encoder@ref with AuthenticationManagerBuilder"() {
		when:
			loadConfig(PasswordEncoderConfig)
			AuthenticationManager authMgr = authenticationManager()
		then:
			authMgr.authenticate(new UsernamePasswordAuthenticationToken("user", "password"))
	}
}
