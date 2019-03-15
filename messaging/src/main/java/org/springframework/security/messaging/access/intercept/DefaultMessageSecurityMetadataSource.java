/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.messaging.access.intercept;

import org.springframework.messaging.Message;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.messaging.access.expression.ExpressionBasedMessageSecurityMetadataSourceFactory;
import org.springframework.security.messaging.util.matcher.MessageMatcher;

import java.util.*;

/**
 * A default implementation of {@link MessageSecurityMetadataSource} that looks up the
 * {@link ConfigAttribute} instances using a {@link MessageMatcher}.
 *
 * <p>
 * Each entry is considered in order. The first entry that matches, the corresponding
 * {@code Collection<ConfigAttribute>} is returned.
 * </p>
 *
 * @see ChannelSecurityInterceptor
 * @see ExpressionBasedMessageSecurityMetadataSourceFactory
 *
 * @since 4.0
 * @author Rob Winch
 */
public final class DefaultMessageSecurityMetadataSource implements
		MessageSecurityMetadataSource {
	private final Map<MessageMatcher<?>, Collection<ConfigAttribute>> messageMap;

	public DefaultMessageSecurityMetadataSource(
			LinkedHashMap<MessageMatcher<?>, Collection<ConfigAttribute>> messageMap) {
		this.messageMap = messageMap;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public Collection<ConfigAttribute> getAttributes(Object object)
			throws IllegalArgumentException {
		final Message message = (Message) object;
		for (Map.Entry<MessageMatcher<?>, Collection<ConfigAttribute>> entry : messageMap
				.entrySet()) {
			if (entry.getKey().matches(message)) {
				return entry.getValue();
			}
		}
		return null;
	}

	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Set<ConfigAttribute> allAttributes = new HashSet<ConfigAttribute>();

		for (Collection<ConfigAttribute> entry : messageMap.values()) {
			allAttributes.addAll(entry);
		}

		return allAttributes;
	}

	public boolean supports(Class<?> clazz) {
		return Message.class.isAssignableFrom(clazz);
	}
}
