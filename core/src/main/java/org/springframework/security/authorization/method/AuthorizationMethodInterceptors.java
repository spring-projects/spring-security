/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.authorization.method;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * A static factory for constructing common {@link AuthorizationMethodInterceptor}s
 *
 * @author Josh Cummings
 * @since 5.5
 * @see PreAuthorizeAuthorizationManager
 * @see PostAuthorizeAuthorizationManager
 * @see SecuredAuthorizationManager
 * @see Jsr250AuthorizationManager
 */
public final class AuthorizationMethodInterceptors {

	public static AuthorizationMethodInterceptor preAuthorize() {
		return preAuthorize(new PreAuthorizeAuthorizationManager());
	}

	public static AuthorizationMethodInterceptor preAuthorize(PreAuthorizeAuthorizationManager manager) {
		return new AuthorizationManagerBeforeMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class), manager);
	}

	public static AuthorizationMethodInterceptor postAuthorize() {
		return postAuthorize(new PostAuthorizeAuthorizationManager());
	}

	public static AuthorizationMethodInterceptor postAuthorize(PostAuthorizeAuthorizationManager manager) {
		return new AuthorizationManagerAfterMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(PostAuthorize.class), manager);
	}

	public static AuthorizationMethodInterceptor secured() {
		return secured(new SecuredAuthorizationManager());
	}

	public static AuthorizationMethodInterceptor secured(SecuredAuthorizationManager manager) {
		return new AuthorizationManagerBeforeMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(Secured.class), manager);
	}

	public static AuthorizationMethodInterceptor jsr250() {
		return jsr250(new Jsr250AuthorizationManager());
	}

	public static AuthorizationMethodInterceptor jsr250(Jsr250AuthorizationManager manager) {
		return new AuthorizationManagerBeforeMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(DenyAll.class, PermitAll.class, RolesAllowed.class),
				manager);
	}

	private AuthorizationMethodInterceptors() {

	}

}
