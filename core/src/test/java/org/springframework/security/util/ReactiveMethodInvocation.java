/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.util;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Stream;

import org.reactivestreams.Publisher;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.util.ReflectionUtils;

/**
 * A {@link SimpleMethodInvocation} that makes it easy to write tests that involve reactive methods.
 *
 * @author Eric Deandrea
 * @since 5.1.2
 */
public class ReactiveMethodInvocation extends SimpleMethodInvocation {
	public ReactiveMethodInvocation(Object targetObject, String methodName, Object... arguments) {
		this(targetObject, ReflectionUtils.findMethod(targetObject.getClass(), methodName, getParameterClasses(arguments)), arguments);
	}

	public ReactiveMethodInvocation(Object targetObject, Method method, Object... arguments) {
		super(targetObject, method, arguments);
	}

	private static Class<?>[] getParameterClasses(Object... arguments) {
		return Optional.ofNullable(arguments)
				.map(Arrays::stream)
				.orElseGet(Stream::empty)
				.map(Object::getClass)
				.map(ReactiveMethodInvocation::getParameterClass)
				.toArray(Class<?>[]::new);
	}

	private static Class<?> getParameterClass(Class<?> clazz) {
		if (Flux.class.isAssignableFrom(clazz)) {
			return Flux.class;
		}
		else if (Mono.class.isAssignableFrom(clazz)) {
			return Mono.class;
		}
		else if (Publisher.class.isAssignableFrom(clazz)) {
			return Publisher.class;
		}

		return clazz;
	}

	@Override
	public Object proceed() throws Throwable {
		Method method = getMethod();
		ReflectionUtils.makeAccessible(method);

		return ReflectionUtils.invokeMethod(method, getThis(), getArguments());
	}
}
