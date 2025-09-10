/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Base configurer for an OAuth 2.0 component (e.g. protocol endpoint).
 *
 * @author Joe Grandja
 * @since 7.0
 */
abstract class AbstractOAuth2Configurer {

	private final ObjectPostProcessor<Object> objectPostProcessor;

	AbstractOAuth2Configurer(ObjectPostProcessor<Object> objectPostProcessor) {
		this.objectPostProcessor = objectPostProcessor;
	}

	abstract void init(HttpSecurity httpSecurity);

	abstract void configure(HttpSecurity httpSecurity);

	abstract RequestMatcher getRequestMatcher();

	protected final <T> T postProcess(T object) {
		return (T) this.objectPostProcessor.postProcess(object);
	}

	protected final ObjectPostProcessor<Object> getObjectPostProcessor() {
		return this.objectPostProcessor;
	}

}
