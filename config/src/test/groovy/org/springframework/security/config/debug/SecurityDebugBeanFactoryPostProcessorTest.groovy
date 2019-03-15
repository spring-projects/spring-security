/*
 * Copyright 2002-2011 the original author or authors.
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
package org.springframework.security.config.debug

import org.springframework.security.config.BeanIds
import org.springframework.security.config.http.AbstractHttpConfigTests
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.debug.DebugFilter;

class SecurityDebugBeanFactoryPostProcessorTest extends AbstractHttpConfigTests {

	// SEC-1885
	def 'SEC-1885 - SecurityDebugBeanFactoryPostProcessor works when dependencies have Autowired constructor'() {
		when: 'debug used and FilterChainProxy has dependency with @Autowired constructor'
		xml.debug()
		httpAutoConfig {}
		xml.'authentication-manager'() {
			'authentication-provider'('ref': 'authProvider')
		}
		xml.'context:component-scan'('base-package':'org.springframework.security.config.debug')
		createAppContext('')
		then: 'TestAuthenticationProvider.<init>() is not thrown'
		appContext.getBean(BeanIds.SPRING_SECURITY_FILTER_CHAIN) instanceof DebugFilter
		appContext.getBean(BeanIds.FILTER_CHAIN_PROXY) instanceof FilterChainProxy
	}
}
