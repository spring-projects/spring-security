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

package org.springframework.security.access.prepost;

import java.lang.reflect.Method;
import java.util.Collection;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.reactivestreams.Publisher;
import reactor.core.Exceptions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.util.Assert;

/**
 * A {@link MethodInterceptor} that supports {@link PreAuthorize} and
 * {@link PostAuthorize} for methods that return {@link Mono} or {@link Flux}
 *
 * @author Rob Winch
 * @since 5.0
 */
public class PrePostAdviceReactiveMethodInterceptor implements MethodInterceptor {

	private Authentication anonymous = new AnonymousAuthenticationToken("key", "anonymous",
			AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private final MethodSecurityMetadataSource attributeSource;

	private final PreInvocationAuthorizationAdvice preInvocationAdvice;

	private final PostInvocationAuthorizationAdvice postAdvice;

	/**
	 * Creates a new instance
	 * @param attributeSource the {@link MethodSecurityMetadataSource} to use
	 * @param preInvocationAdvice the {@link PreInvocationAuthorizationAdvice} to use
	 * @param postInvocationAdvice the {@link PostInvocationAuthorizationAdvice} to use
	 */
	public PrePostAdviceReactiveMethodInterceptor(MethodSecurityMetadataSource attributeSource,
			PreInvocationAuthorizationAdvice preInvocationAdvice,
			PostInvocationAuthorizationAdvice postInvocationAdvice) {
		Assert.notNull(attributeSource, "attributeSource cannot be null");
		Assert.notNull(preInvocationAdvice, "preInvocationAdvice cannot be null");
		Assert.notNull(postInvocationAdvice, "postInvocationAdvice cannot be null");

		this.attributeSource = attributeSource;
		this.preInvocationAdvice = preInvocationAdvice;
		this.postAdvice = postInvocationAdvice;
	}

	@Override
	public Object invoke(final MethodInvocation invocation) {
		Method method = invocation.getMethod();
		Class<?> returnType = method.getReturnType();
		if (!Publisher.class.isAssignableFrom(returnType)) {
			throw new IllegalStateException("The returnType " + returnType + " on " + method
					+ " must return an instance of org.reactivestreams.Publisher (i.e. Mono / Flux) in order to support Reactor Context");
		}
		Class<?> targetClass = invocation.getThis().getClass();
		Collection<ConfigAttribute> attributes = this.attributeSource.getAttributes(method, targetClass);

		PreInvocationAttribute preAttr = findPreInvocationAttribute(attributes);
		Mono<Authentication> toInvoke = ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication).defaultIfEmpty(this.anonymous)
				.filter(auth -> this.preInvocationAdvice.before(auth, invocation, preAttr))
				.switchIfEmpty(Mono.defer(() -> Mono.error(new AccessDeniedException("Denied"))));

		PostInvocationAttribute attr = findPostInvocationAttribute(attributes);

		if (Mono.class.isAssignableFrom(returnType)) {
			return toInvoke.flatMap(auth -> this.<Mono<?>>proceed(invocation)
					.map(r -> attr == null ? r : this.postAdvice.after(auth, invocation, attr, r)));
		}

		if (Flux.class.isAssignableFrom(returnType)) {
			return toInvoke.flatMapMany(auth -> this.<Flux<?>>proceed(invocation)
					.map(r -> attr == null ? r : this.postAdvice.after(auth, invocation, attr, r)));
		}

		return toInvoke.flatMapMany(auth -> Flux.from(this.<Publisher<?>>proceed(invocation))
				.map(r -> attr == null ? r : this.postAdvice.after(auth, invocation, attr, r)));
	}

	private static <T extends Publisher<?>> T proceed(final MethodInvocation invocation) {
		try {
			return (T) invocation.proceed();
		}
		catch (Throwable throwable) {
			throw Exceptions.propagate(throwable);
		}
	}

	private static PostInvocationAttribute findPostInvocationAttribute(Collection<ConfigAttribute> config) {
		for (ConfigAttribute attribute : config) {
			if (attribute instanceof PostInvocationAttribute) {
				return (PostInvocationAttribute) attribute;
			}
		}

		return null;
	}

	private static PreInvocationAttribute findPreInvocationAttribute(Collection<ConfigAttribute> config) {
		for (ConfigAttribute attribute : config) {
			if (attribute instanceof PreInvocationAttribute) {
				return (PreInvocationAttribute) attribute;
			}
		}

		return null;
	}

}
