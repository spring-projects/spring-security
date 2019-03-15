/*
 * Copyright 2002-2015 the original author or authors.
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
package org.springframework.security.config.http

import static org.springframework.security.config.ConfigTestUtils.AUTH_PROVIDER_XML

import javax.sql.DataSource

import org.springframework.beans.FatalBeanException
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException
import org.springframework.security.TestDataSource
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.RememberMeAuthenticationProvider
import org.springframework.security.core.userdetails.MockUserDetailsService
import org.springframework.security.util.FieldUtils
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices

/**
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author Oliver Becker
 */
class RememberMeConfigTests extends AbstractHttpConfigTests {

	def rememberMeServiceWorksWithTokenRepoRef() {
		httpAutoConfig () {
			'remember-me'('token-repository-ref': 'tokenRepo')
		}
		bean('tokenRepo', CustomTokenRepository.class.name)

		createAppContext(AUTH_PROVIDER_XML)

		def rememberMeServices	= rememberMeServices()

		expect:
		rememberMeServices instanceof PersistentTokenBasedRememberMeServices
		rememberMeServices.tokenRepository instanceof CustomTokenRepository
		FieldUtils.getFieldValue(rememberMeServices, "useSecureCookie") == null
	}

	def rememberMeServiceWorksWithDataSourceRef() {
		httpAutoConfig () {
			'remember-me'('data-source-ref': 'ds')
		}
		bean('ds', TestDataSource.class.name, ['tokendb'])

		createAppContext(AUTH_PROVIDER_XML)

		def rememberMeServices	= rememberMeServices()

		expect:
		rememberMeServices instanceof PersistentTokenBasedRememberMeServices
		rememberMeServices.tokenRepository instanceof JdbcTokenRepositoryImpl
	}

	def rememberMeServiceWorksWithAuthenticationSuccessHandlerRef() {
		httpAutoConfig () {
			'remember-me'('authentication-success-handler-ref': 'sh')
		}
		bean('sh', SimpleUrlAuthenticationSuccessHandler.class.name, ['/target'])

		createAppContext(AUTH_PROVIDER_XML)

		expect:
		getFilter(RememberMeAuthenticationFilter.class).successHandler instanceof SimpleUrlAuthenticationSuccessHandler
	}

	def rememberMeServiceWorksWithExternalServicesImpl() {
		httpAutoConfig () {
			'remember-me'('key': "#{'our' + 'key'}", 'services-ref': 'rms')
			csrf(disabled:true)
		}
		xml.'b:bean'(id: 'rms', 'class': TokenBasedRememberMeServices.class.name) {
			'b:constructor-arg'(value: 'ourKey')
			'b:constructor-arg'(ref: 'us')
			'b:property'(name: 'tokenValiditySeconds', value: '5000')
		}

		createAppContext(AUTH_PROVIDER_XML)

		List logoutHandlers = FieldUtils.getFieldValue(getFilter(LogoutFilter.class), "handlers");
		Map ams = appContext.getBeansOfType(ProviderManager.class);
		ProviderManager am = (ams.values() as List).find { it instanceof ProviderManager && it.providers.size() == 2}
		RememberMeAuthenticationProvider rmp = am.providers.find { it instanceof RememberMeAuthenticationProvider}

		expect:
		rmp != null
		5000 == FieldUtils.getFieldValue(rememberMeServices(), "tokenValiditySeconds")
		// SEC-909
		logoutHandlers.size() == 2
		logoutHandlers.get(1) == rememberMeServices()
		// SEC-1281
		rmp.key == "ourkey"
	}

	def rememberMeAddsLogoutHandlerToLogoutFilter() {
		httpAutoConfig () {
			'remember-me'()
			csrf(disabled:true)
		}
		createAppContext(AUTH_PROVIDER_XML)

		def rememberMeServices = rememberMeServices()
		List logoutHandlers = getFilter(LogoutFilter.class).handlers

		expect:
		rememberMeServices
		logoutHandlers.size() == 2
		logoutHandlers.get(0) instanceof SecurityContextLogoutHandler
		logoutHandlers.get(1) == rememberMeServices
	}

	def rememberMeTokenValidityIsParsedCorrectly() {
		httpAutoConfig () {
			'remember-me'('key': 'ourkey', 'token-validity-seconds':'10000')
		}

		createAppContext(AUTH_PROVIDER_XML)

		def rememberMeServices = rememberMeServices()
		def rememberMeFilter = getFilter(RememberMeAuthenticationFilter.class)

		expect:
		rememberMeFilter.authenticationManager
		rememberMeServices.key == 'ourkey'
		rememberMeServices.tokenValiditySeconds == 10000
		rememberMeServices.userDetailsService
	}

	def 'Remember-me token validity allows negative value for non-persistent implementation'() {
		httpAutoConfig () {
			'remember-me'('key': 'ourkey', 'token-validity-seconds':'-1')
		}

		createAppContext(AUTH_PROVIDER_XML)
		expect:
		rememberMeServices().tokenValiditySeconds == -1
	}

	def 'remember-me@token-validity-seconds denies for persistent implementation'() {
		setup:
			httpAutoConfig () {
				'remember-me'('key': 'ourkey', 'token-validity-seconds':'-1', 'dataSource' : 'dataSource')
			}
			mockBean(DataSource)
		when:
			createAppContext(AUTH_PROVIDER_XML)
		then:
			thrown(FatalBeanException)
	}

	def 'SEC-2165: remember-me@token-validity-seconds allows property placeholders'() {
		when:
			httpAutoConfig () {
				'remember-me'('key': 'ourkey', 'token-validity-seconds':'${security.rememberme.ttl}')
			}
			xml.'b:bean'(class: PropertyPlaceholderConfigurer.name) {
				'b:property'(name:'properties', value:'security.rememberme.ttl=30')
			}

			createAppContext(AUTH_PROVIDER_XML)
		then:
			rememberMeServices().tokenValiditySeconds == 30
	}

	def rememberMeSecureCookieAttributeIsSetCorrectly() {
		httpAutoConfig () {
			'remember-me'('key': 'ourkey', 'use-secure-cookie':'true')
		}

		createAppContext(AUTH_PROVIDER_XML)
		expect:
		FieldUtils.getFieldValue(rememberMeServices(), "useSecureCookie")
	}

	// SEC-1827
	def rememberMeSecureCookieAttributeFalse() {
		httpAutoConfig () {
			'remember-me'('key': 'ourkey', 'use-secure-cookie':'false')
		}

		createAppContext(AUTH_PROVIDER_XML)
		expect: 'useSecureCookie is false'
		FieldUtils.getFieldValue(rememberMeServices(), "useSecureCookie") == Boolean.FALSE
	}

	def 'Negative token-validity is rejected with persistent implementation'() {
		when:
		httpAutoConfig () {
			'remember-me'('key': 'ourkey', 'token-validity-seconds':'-1', 'token-repository-ref': 'tokenRepo')
		}
		bean('tokenRepo', InMemoryTokenRepositoryImpl.class.name)
		createAppContext(AUTH_PROVIDER_XML)

		then:
		BeanDefinitionParsingException e = thrown()
	}

	def 'Custom user service is supported'() {
		when:
		httpAutoConfig () {
			'remember-me'('key': 'ourkey', 'token-validity-seconds':'-1', 'user-service-ref': 'userService')
		}
		bean('userService', MockUserDetailsService.class.name)
		createAppContext(AUTH_PROVIDER_XML)

		then: "Parses OK"
		notThrown BeanDefinitionParsingException
	}

	// SEC-742
	def rememberMeWorksWithoutBasicProcessingFilter() {
		when:
		xml.http () {
			'form-login'('login-page': '/login.jsp', 'default-target-url': '/messageList.html' )
			logout('logout-success-url': '/login.jsp')
			anonymous(username: 'guest', 'granted-authority': 'guest')
			'remember-me'()
		}
		createAppContext(AUTH_PROVIDER_XML)

		then: "Parses OK"
		notThrown BeanDefinitionParsingException
	}

	def 'Default remember-me-parameter is correct'() {
		httpAutoConfig () {
			'remember-me'()
		}

		createAppContext(AUTH_PROVIDER_XML)
		expect:
		rememberMeServices().parameter == AbstractRememberMeServices.DEFAULT_PARAMETER
	}

	// SEC-2119
	def 'Custom remember-me-parameter is supported'() {
		httpAutoConfig () {
			'remember-me'('remember-me-parameter': 'ourParam')
		}

		createAppContext(AUTH_PROVIDER_XML)
		expect:
		rememberMeServices().parameter == 'ourParam'
	}

	def 'remember-me-parameter cannot be used together with services-ref'() {
		when:
		httpAutoConfig () {
			'remember-me'('remember-me-parameter': 'ourParam', 'services-ref': 'ourService')
		}
		createAppContext(AUTH_PROVIDER_XML)
		then:
		BeanDefinitionParsingException e = thrown()
	}

	// SEC-2826
	def 'Custom remember-me-cookie is supported'() {
		httpAutoConfig () {
			'remember-me'('remember-me-cookie': 'ourCookie')
		}

		createAppContext(AUTH_PROVIDER_XML)
		expect:
		rememberMeServices().cookieName == 'ourCookie'
	}

	// SEC-2826
	def 'remember-me-cookie cannot be used together with services-ref'() {
		when:
		httpAutoConfig () {
			'remember-me'('remember-me-cookie': 'ourCookie', 'services-ref': 'ourService')
		}

		createAppContext(AUTH_PROVIDER_XML)
		then:
		BeanDefinitionParsingException e = thrown()
		expect:
		e.message == 'Configuration problem: services-ref can\'t be used in combination with attributes token-repository-ref,data-source-ref, user-service-ref, token-validity-seconds, use-secure-cookie, remember-me-parameter or remember-me-cookie\nOffending resource: null'
	}

	def rememberMeServices() {
		getFilter(RememberMeAuthenticationFilter.class).getRememberMeServices()
	}

	static class CustomTokenRepository extends InMemoryTokenRepositoryImpl {

	}
}
