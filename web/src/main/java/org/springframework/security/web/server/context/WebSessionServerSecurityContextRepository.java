/*
 * Copyright 2002-2020 the original author or authors.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

/**
 * Stores the {@link SecurityContext} in the
 * {@link org.springframework.web.server.WebSession}. When a {@link SecurityContext} is
 * saved, the session id is changed to prevent session fixation attacks.
 *
 * @author Rob Winch
 * @author Mathieu Ouellet
 * @since 5.0
 */
public class WebSessionServerSecurityContextRepository implements ServerSecurityContextRepository {

	private static final Log logger = LogFactory.getLog(WebSessionServerSecurityContextRepository.class);

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

	@Override
	public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
		return exchange.getSession().doOnNext((session) -> {
			if (context == null) {
				session.getAttributes().remove(this.springSecurityContextAttrName);
				logger.debug(LogMessage.format("Removed SecurityContext stored in WebSession: '%s'", session));
			}
			else {
				session.getAttributes().put(this.springSecurityContextAttrName, context);
				logger.debug(LogMessage.format("Saved SecurityContext '%s' in WebSession: '%s'", context, session));
			}
		}).flatMap(WebSession::changeSessionId);
	}

	@Override
	public Mono<SecurityContext> load(ServerWebExchange exchange) {
		return exchange.getSession().flatMap((session) -> {
			SecurityContext context = (SecurityContext) session.getAttribute(this.springSecurityContextAttrName);
			logger.debug((context != null)
					? LogMessage.format("Found SecurityContext '%s' in WebSession: '%s'", context, session)
					: LogMessage.format("No SecurityContext found in WebSession: '%s'", session));
			return Mono.justOrEmpty(context);
		});
	}

}
