/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.web.server.context;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

/**
 * Stores the {@link SecurityContext} in the
 * {@link org.springframework.web.server.WebSession}. When a {@link SecurityContext} is
 * saved, the session id is changed to prevent session fixation attacks.
 * @author Rob Winch
 * @since 5.0
 */
public class WebSessionServerSecurityContextRepository
	implements ServerSecurityContextRepository {

	/**
	 * The default session attribute name to save and load the {@link SecurityContext}
	 */
	public static final String DEFAULT_SPRING_SECURITY_CONTEXT_ATTR_NAME = "SPRING_SECURITY_CONTEXT";

	private String springSecurityContextAttrName = DEFAULT_SPRING_SECURITY_CONTEXT_ATTR_NAME;

	/**
	 * Sets the session attribute name used to save and load the {@link SecurityContext}
	 * @param springSecurityContextAttrName the session attribute name to use to save and
	 * load the {@link SecurityContext}
	 */
	public void setSpringSecurityContextAttrName(String springSecurityContextAttrName) {
		Assert.hasText(springSecurityContextAttrName, "springSecurityContextAttrName cannot be null or empty");
		this.springSecurityContextAttrName = springSecurityContextAttrName;
	}

	public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
		return exchange.getSession()
			.doOnNext(session -> {
				if (context == null) {
					session.getAttributes().remove(this.springSecurityContextAttrName);
				} else {
					session.getAttributes().put(this.springSecurityContextAttrName, context);
				}
			})
			.flatMap(session -> session.changeSessionId());
	}

	public Mono<SecurityContext> load(ServerWebExchange exchange) {
		return exchange.getSession()
			.map(WebSession::getAttributes)
			.flatMap( attrs -> {
				SecurityContext context = (SecurityContext) attrs.get(this.springSecurityContextAttrName);
				return Mono.justOrEmpty(context);
			});
	}
}
