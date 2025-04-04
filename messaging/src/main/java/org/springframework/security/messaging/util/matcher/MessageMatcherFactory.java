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

package org.springframework.security.messaging.util.matcher;

import org.springframework.context.ApplicationContext;
import org.springframework.messaging.simp.SimpMessageType;

/**
 * This utility exists only to facilitate applications opting into using path patterns in
 * the Message Security DSL. It is for internal use only.
 *
 * @deprecated
 */
@Deprecated(forRemoval = true)
public final class MessageMatcherFactory {

	private static PathPatternMessageMatcher.Builder builder;

	public static void setApplicationContext(ApplicationContext context) {
		builder = context.getBeanProvider(PathPatternMessageMatcher.Builder.class).getIfUnique();
	}

	public static boolean usesPathPatterns() {
		return builder != null;
	}

	public static MessageMatcher<?> matcher(String destination) {
		return matcher(null, destination);
	}

	public static MessageMatcher<Object> matcher(SimpMessageType type, String destination) {
		return builder.matcher(type, destination);
	}

	private MessageMatcherFactory() {
	}

}
