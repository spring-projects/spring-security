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

package org.springframework.security.config.annotation.method.configuration;

import java.util.List;

import reactor.core.publisher.Mono;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;

public class ReactiveMethodSecurityServiceImpl implements ReactiveMethodSecurityService {

	@Override
	public Mono<String> preAuthorizeUser() {
		return Mono.just("user");
	}

	@Override
	public Mono<String> preAuthorizeAdmin() {
		return Mono.just("admin");
	}

	@Override
	public Mono<String> preAuthorizeGetCardNumberIfAdmin(String cardNumber) {
		return Mono.just(cardNumber);
	}

	@Override
	public Mono<String> preAuthorizeWithHandlerChildGetCardNumberIfAdmin(String cardNumber) {
		return Mono.just(cardNumber);
	}

	@Override
	public Mono<String> preAuthorizeThrowAccessDeniedManually() {
		return Mono.error(new AuthorizationDeniedException("Access Denied", new AuthorizationDecision(false)));
	}

	@Override
	public Mono<String> postAuthorizeGetCardNumberIfAdmin(String cardNumber) {
		return Mono.just(cardNumber);
	}

	@Override
	public Mono<String> postAuthorizeThrowAccessDeniedManually() {
		return Mono.error(new AuthorizationDeniedException("Access Denied", new AuthorizationDecision(false)));
	}

	@Override
	public Mono<String> preAuthorizeDeniedMethodWithMaskAnnotation() {
		return Mono.just("ok");
	}

	@Override
	public Mono<String> preAuthorizeDeniedMethodWithNoMaskAnnotation() {
		return Mono.just("ok");
	}

	@Override
	public Mono<String> postAuthorizeDeniedWithNullDenied() {
		return Mono.just("ok");
	}

	@Override
	public Mono<String> postAuthorizeDeniedMethodWithMaskAnnotation() {
		return Mono.just("ok");
	}

	@Override
	public Mono<String> postAuthorizeDeniedMethodWithNoMaskAnnotation() {
		return Mono.just("ok");
	}

	@Override
	public Mono<String> preAuthorizeWithMaskAnnotationUsingBean() {
		return Mono.just("ok");
	}

	@Override
	public Mono<String> postAuthorizeWithMaskAnnotationUsingBean() {
		return Mono.just("ok");
	}

	@Override
	public Mono<String> checkCustomResult(boolean result) {
		return Mono.just("ok");
	}

	@Override
	public Mono<String> preAuthorizeHasPermission(String kgName) {
		return Mono.just("ok");
	}

	@Override
	public Mono<List<String>> manyAnnotations(Mono<List<String>> array) {
		return array;
	}

}
