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

package org.springframework.security.config.http;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.security.messaging.util.matcher.PathPatternMessageMatcher;
import org.springframework.security.messaging.util.matcher.SimpDestinationMessageMatcher;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

@Deprecated
public final class MessageMatcherFactoryBean implements FactoryBean<MessageMatcher<?>>, ApplicationContextAware {

	private PathPatternMessageMatcher.Builder builder;

	private final SimpMessageType method;

	private final String path;

	private PathMatcher pathMatcher = new AntPathMatcher();

	public MessageMatcherFactoryBean(String path) {
		this(path, null);
	}

	public MessageMatcherFactoryBean(String path, SimpMessageType method) {
		this.method = method;
		this.path = path;
	}

	@Override
	public MessageMatcher<?> getObject() throws Exception {
		if (this.builder != null) {
			return this.builder.matcher(this.method, this.path);
		}
		if (this.method == SimpMessageType.SUBSCRIBE) {
			return SimpDestinationMessageMatcher.createSubscribeMatcher(this.path, this.pathMatcher);
		}
		if (this.method == SimpMessageType.MESSAGE) {
			return SimpDestinationMessageMatcher.createMessageMatcher(this.path, this.pathMatcher);
		}
		return new SimpDestinationMessageMatcher(this.path, this.pathMatcher);
	}

	@Override
	public Class<?> getObjectType() {
		return null;
	}

	public void setPathMatcher(PathMatcher pathMatcher) {
		this.pathMatcher = pathMatcher;
	}

	@Override
	public void setApplicationContext(ApplicationContext context) throws BeansException {
		this.builder = context.getBeanProvider(PathPatternMessageMatcher.Builder.class).getIfUnique();
	}

}
