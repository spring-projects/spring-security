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

package org.springframework.security.config.http;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.security.messaging.util.matcher.PathPatternMessageMatcher;

@Deprecated
public final class MessageMatcherFactoryBean implements FactoryBean<MessageMatcher<?>>, ApplicationContextAware {

	private PathPatternMessageMatcher.Builder builder;

	private final SimpMessageType method;

	private final String path;

	public MessageMatcherFactoryBean(String path) {
		this(path, null);
	}

	public MessageMatcherFactoryBean(String path, SimpMessageType method) {
		this.method = method;
		this.path = path;
	}

	@Override
	public MessageMatcher<?> getObject() throws Exception {
		return this.builder.matcher(this.method, this.path);
	}

	@Override
	public Class<?> getObjectType() {
		return null;
	}

	@Override
	public void setApplicationContext(ApplicationContext context) throws BeansException {
		this.builder = context.getBean(PathPatternMessageMatcher.Builder.class);
	}

}
