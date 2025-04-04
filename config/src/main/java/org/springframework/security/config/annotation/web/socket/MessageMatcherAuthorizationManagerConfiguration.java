/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.config.annotation.web.socket;

import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.messaging.simp.annotation.support.SimpAnnotationMethodMessageHandler;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.messaging.util.matcher.MessageMatcherFactory;
import org.springframework.util.AntPathMatcher;

final class MessageMatcherAuthorizationManagerConfiguration {

	@Bean
	@Scope("prototype")
	MessageMatcherDelegatingAuthorizationManager.Builder messageAuthorizationManagerBuilder(
			ApplicationContext context) {
		MessageMatcherFactory.setApplicationContext(context);
		return MessageMatcherDelegatingAuthorizationManager.builder()
			.simpDestPathMatcher(
					() -> (context.getBeanNamesForType(SimpAnnotationMethodMessageHandler.class).length > 0)
							? context.getBean(SimpAnnotationMethodMessageHandler.class).getPathMatcher()
							: new AntPathMatcher());
	}

}
