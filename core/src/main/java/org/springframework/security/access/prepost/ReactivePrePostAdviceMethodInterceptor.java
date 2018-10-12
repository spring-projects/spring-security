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

package org.springframework.security.access.prepost;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Optional;

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
 * A {@link MethodInterceptor} that supports {@link PreAuthorize} and {@link PostAuthorize} for methods that return
 * {@link Mono} or {@link Flux}.
 * <p>
 *   This class differs from {@link PrePostAdviceReactiveMethodInterceptor} in that this supports
 *   pre/post expressions that return reactive types, whereas {@link PrePostAdviceReactiveMethodInterceptor}
 *   only supports pre/post expressions that are non reactive - just applied to methods that
 *   return reactive types.
 * </p>
 * <p>
 *   For example, this class supports this scenario:
 * </p>
 * <pre>
 *   {@literal @}PreAuthorize("@someBean.hasPermission()")
 *   public Flux{@literal <}String{@literal >} someMethodReturningAFlux() {
 *     ...
 *     return someFlux;
 *   }
 *
 *   {@literal @}Component
 *   public class SomeBean {
 *     public Mono{@literal <}Boolean{@literal >} hasPermission() {
 *       ...
 *       return someBooleanMono;
 *     }
 *   }
 * </pre>
 * <p>
 *   {@link PrePostAdviceReactiveMethodInterceptor} supports putting expressions on methods
 *   that return reactive types, but the methods in the expressions themselves can't return
 *   reactive types.
 * </p>
 *
 * @author Eric Deandrea
 * @since 5.1.2
 */
public class ReactivePrePostAdviceMethodInterceptor implements MethodInterceptor {
	private Authentication anonymous = new AnonymousAuthenticationToken("key", "anonymous",
			AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private final MethodSecurityMetadataSource attributeSource;
	private final ReactivePreInvocationAuthorizationAdvice preInvocationAdvice;
	private final ReactivePostInvocationAuthorizationAdvice postInvocationAdvice;

	/**
	 * Creates a new instance
	 * @param attributeSource the {@link MethodSecurityMetadataSource} to use
	 * @param preInvocationAdvice the {@link ReactivePreInvocationAuthorizationAdvice} to use
	 * @param postInvocationAdvice the {@link ReactivePostInvocationAuthorizationAdvice} to use
	 * @since 5.1.2
	 */
	public ReactivePrePostAdviceMethodInterceptor(MethodSecurityMetadataSource attributeSource,
			ReactivePreInvocationAuthorizationAdvice preInvocationAdvice, ReactivePostInvocationAuthorizationAdvice postInvocationAdvice) {
		Assert.notNull(attributeSource, "attributeSource cannot be null");
		Assert.notNull(preInvocationAdvice, "preInvocationAdvice cannot be null");
		Assert.notNull(postInvocationAdvice, "postInvocationAdvice cannot be null");

		this.attributeSource = attributeSource;
		this.preInvocationAdvice = preInvocationAdvice;
		this.postInvocationAdvice = postInvocationAdvice;
	}

	@Override
	public Object invoke(final MethodInvocation invocation) throws Throwable {
		Method method = invocation.getMethod();
		Class<?> returnType = method.getReturnType();

		if (!Publisher.class.isAssignableFrom(returnType)) {
			throw new IllegalStateException(String.format("The return type %s on method %s must return an instance of %s (i.e. Mono / Flux) in order to support Reactor Context", returnType.getName(), method, Publisher.class.getName()));
		}

		Class<?> targetClass = invocation.getThis().getClass();
		Collection<ConfigAttribute> attributes = this.attributeSource.getAttributes(method, targetClass);

		Optional<PreInvocationAttribute> preAttr = findPreInvocationAttribute(attributes);
		Mono<Authentication> toInvoke = ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.defaultIfEmpty(this.anonymous)
				.filterWhen(auth -> preAttr
						.map(attr -> this.preInvocationAdvice.before(auth, invocation, attr))
						.orElseGet(() -> Mono.defer(() -> Mono.just(true)))
				)
				.switchIfEmpty(Mono.defer(() -> Mono.error(new AccessDeniedException("Denied"))));

		Optional<PostInvocationAttribute> postAttr = findPostInvocationAttribute(attributes);

		if (Mono.class.isAssignableFrom(returnType)) {
			return toInvoke
					.flatMap(auth -> after(postAttr, auth, invocation, proceed(invocation)));
		}
		else if (Flux.class.isAssignableFrom(returnType)) {
			return toInvoke
					.flatMapMany(auth -> after(postAttr, auth, invocation, proceed(invocation)));
		}

		return toInvoke
				.flatMapMany(auth -> after(postAttr, auth, invocation, Flux.from(proceed(invocation))));
	}

	private <P extends Publisher<?>> P after(Optional<PostInvocationAttribute> postAttr, Authentication auth, MethodInvocation mi, P returnPublisher) {
		return postAttr
				.map(attr -> this.postInvocationAdvice.after(auth, mi, attr, returnPublisher))
				.orElseGet(() -> returnPublisher);
	}

	private static <T extends Publisher<?>> T proceed(final MethodInvocation invocation) {
		try {
			return (T) invocation.proceed();
		}
		catch (Throwable throwable) {
			throw Exceptions.propagate(throwable);
		}
	}

	private static Optional<PostInvocationAttribute> findPostInvocationAttribute(Collection<ConfigAttribute> config) {
		return config.stream()
				.filter(PostInvocationAttribute.class::isInstance)
				.map(PostInvocationAttribute.class::cast)
				.findFirst();
	}

	private static Optional<PreInvocationAttribute> findPreInvocationAttribute(Collection<ConfigAttribute> config) {
		return config.stream()
				.filter(PreInvocationAttribute.class::isInstance)
				.map(PreInvocationAttribute.class::cast)
				.findFirst();
	}
}
