/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.web.server;

import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;

import java.util.function.Function;

/**
 * Converts a ServerWebExchange into a UsernamePasswordAuthenticationToken from the form
 * data HTTP parameters.
 *
 * @author Rob Winch
 * @since 5.0
 * @deprecated use
 * {@link org.springframework.security.web.server.authentication.ServerFormLoginAuthenticationConverter}
 * instead.
 */
@Deprecated
public class ServerFormLoginAuthenticationConverter implements Function<ServerWebExchange, Mono<Authentication>> {

	private String usernameParameter = "username";

	private String passwordParameter = "password";

	@Override
	@Deprecated
	public Mono<Authentication> apply(ServerWebExchange exchange) {
		return exchange.getFormData().map(data -> createAuthentication(data));
	}

	private UsernamePasswordAuthenticationToken createAuthentication(MultiValueMap<String, String> data) {
		String username = data.getFirst(this.usernameParameter);
		String password = data.getFirst(this.passwordParameter);
		return new UsernamePasswordAuthenticationToken(username, password);
	}

	/**
	 * The parameter name of the form data to extract the username
	 * @param usernameParameter the username HTTP parameter
	 */
	public void setUsernameParameter(String usernameParameter) {
		Assert.notNull(usernameParameter, "usernameParameter cannot be null");
		this.usernameParameter = usernameParameter;
	}

	/**
	 * The parameter name of the form data to extract the password
	 * @param passwordParameter the password HTTP parameter
	 */
	public void setPasswordParameter(String passwordParameter) {
		Assert.notNull(passwordParameter, "passwordParameter cannot be null");
		this.passwordParameter = passwordParameter;
	}

}
