/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authorization;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.aop.framework.ProxyFactory;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationManagerAfterReactiveMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeReactiveMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizeReturnObjectMethodInterceptor;
import org.springframework.security.authorization.method.PostFilterAuthorizationReactiveMethodInterceptor;
import org.springframework.security.authorization.method.PreFilterAuthorizationReactiveMethodInterceptor;

/**
 * A proxy factory for applying authorization advice to an arbitrary object.
 *
 * <p>
 * For example, consider a non-Spring-managed object {@code Foo}: <pre>
 *     class Foo {
 *         &#064;PreAuthorize("hasAuthority('bar:read')")
 *         String bar() { ... }
 *     }
 * </pre>
 *
 * Use {@link ReactiveAuthorizationAdvisorProxyFactory} to wrap the instance in Spring
 * Security's {@link org.springframework.security.access.prepost.PreAuthorize} method
 * interceptor like so:
 *
 * <pre>
 *     AuthorizationManagerBeforeMethodInterceptor preAuthorize = AuthorizationManagerBeforeMethodInterceptor.preAuthorize();
 *     AuthorizationProxyFactory proxyFactory = new AuthorizationProxyFactory(preAuthorize);
 *     Foo foo = new Foo();
 *     foo.bar(); // passes
 *     Foo securedFoo = proxyFactory.proxy(foo);
 *     securedFoo.bar(); // access denied!
 * </pre>
 *
 * @author Josh Cummings
 * @since 6.3
 */
public final class ReactiveAuthorizationAdvisorProxyFactory implements AuthorizationProxyFactory {

	private final AuthorizationAdvisorProxyFactory defaults = new AuthorizationAdvisorProxyFactory();

	public ReactiveAuthorizationAdvisorProxyFactory() {
		List<AuthorizationAdvisor> advisors = new ArrayList<>();
		advisors.add(AuthorizationManagerBeforeReactiveMethodInterceptor.preAuthorize());
		advisors.add(AuthorizationManagerAfterReactiveMethodInterceptor.postAuthorize());
		advisors.add(new PreFilterAuthorizationReactiveMethodInterceptor());
		advisors.add(new PostFilterAuthorizationReactiveMethodInterceptor());
		advisors.add(new AuthorizeReturnObjectMethodInterceptor(this));
		this.defaults.setAdvisors(advisors);
	}

	/**
	 * Proxy an object to enforce authorization advice.
	 *
	 * <p>
	 * Proxies any instance of a non-final class or a class that implements more than one
	 * interface.
	 *
	 * <p>
	 * If {@code target} is an {@link Iterator}, {@link Collection}, {@link Array},
	 * {@link Map}, {@link Stream}, or {@link Optional}, then the element or value type is
	 * proxied.
	 *
	 * <p>
	 * If {@code target} is a {@link Class}, then {@link ProxyFactory#getProxyClass} is
	 * invoked instead.
	 * @param target the instance to proxy
	 * @return the proxied instance
	 */
	@Override
	public Object proxy(Object target) {
		if (target instanceof Mono<?> mono) {
			return proxyMono(mono);
		}
		if (target instanceof Flux<?> flux) {
			return proxyFlux(flux);
		}
		return this.defaults.proxy(target);
	}

	/**
	 * Add advisors that should be included to each proxy created.
	 *
	 * <p>
	 * All advisors are re-sorted by their advisor order.
	 * @param advisors the advisors to add
	 */
	public void setAdvisors(AuthorizationAdvisor... advisors) {
		this.defaults.setAdvisors(advisors);
	}

	/**
	 * Add advisors that should be included to each proxy created.
	 *
	 * <p>
	 * All advisors are re-sorted by their advisor order.
	 * @param advisors the advisors to add
	 */
	public void setAdvisors(Collection<AuthorizationAdvisor> advisors) {
		this.defaults.setAdvisors(advisors);
	}

	private Mono<?> proxyMono(Mono<?> mono) {
		return mono.map(this::proxy);
	}

	private Flux<?> proxyFlux(Flux<?> flux) {
		return flux.map(this::proxy);
	}

}
