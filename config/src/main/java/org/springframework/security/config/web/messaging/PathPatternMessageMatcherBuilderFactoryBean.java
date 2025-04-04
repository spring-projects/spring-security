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

package org.springframework.security.config.web.messaging;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager;
import org.springframework.security.messaging.util.matcher.PathPatternMessageMatcher;

/**
 * Use this factory bean to configure the {@link PathPatternMessageMatcher.Builder} bean
 * used to create request matchers in {@link MessageMatcherDelegatingAuthorizationManager}
 * and other parts of the DSL.
 *
 * @author Pat McCusker
 * @since 6.5
 */
public final class PathPatternMessageMatcherBuilderFactoryBean
		implements FactoryBean<PathPatternMessageMatcher.Builder> {

	@Override
	public PathPatternMessageMatcher.Builder getObject() throws Exception {
		return PathPatternMessageMatcher.withDefaults();
	}

	@Override
	public Class<?> getObjectType() {
		return PathPatternMessageMatcher.Builder.class;
	}

}
