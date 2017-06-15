/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.springframework.security.config.annotation.web.reactive;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.HttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainFilter;
import org.springframework.util.ObjectUtils;

import java.util.Arrays;
import java.util.List;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Configuration
public class WebFluxSecurityConfiguration {

	@Autowired(required = false)
	private List<SecurityWebFilterChain> securityWebFilterChains;

	@Autowired
	ApplicationContext context;

	@Bean
	public WebFilterChainFilter springSecurityFilterChain() {
		return WebFilterChainFilter.fromSecurityWebFilterChainsList(getSecurityWebFilterChains());
	}

	private List<SecurityWebFilterChain> getSecurityWebFilterChains() {
		List<SecurityWebFilterChain> result = securityWebFilterChains;
		if(ObjectUtils.isEmpty(result)) {
			return defaultSecurityWebFilterChains();
		}
		return result;
	}

	private List<SecurityWebFilterChain> defaultSecurityWebFilterChains() {
		HttpSecurity http = context.getBean(HttpSecurity.class);
		http
			.authorizeExchange()
				.anyExchange().authenticated();
		return Arrays.asList(http.build());
	}
}
