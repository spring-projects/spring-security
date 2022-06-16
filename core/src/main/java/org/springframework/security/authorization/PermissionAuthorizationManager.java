/*
 * Copyright 2002-2022 the original author or authors.
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

import java.util.function.Supplier;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.DenyAllPermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} that can determine access to the {@link T} object by
 * evaluating if user has required permission using provided {@link PermissionEvaluator}.
 *
 * @param <T> the type of object being authorized
 * @author Evgeniy Cheban
 * @since 5.8
 */
public final class PermissionAuthorizationManager<T> implements AuthorizationManager<T> {

	private PermissionEvaluator permissionEvaluator = new DenyAllPermissionEvaluator();

	private final Object permission;

	/**
	 * Creates an instance.
	 * @param permission the permission to use
	 */
	public PermissionAuthorizationManager(Object permission) {
		Assert.notNull(permission, "permission cannot be empty");
		this.permission = permission;
	}

	/**
	 * Sets the {@link PermissionEvaluator} to be used. Default is
	 * {@link DenyAllPermissionEvaluator}. Cannot be null.
	 */
	public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
		Assert.notNull(permissionEvaluator, "permissionEvaluator cannot be null");
		this.permissionEvaluator = permissionEvaluator;
	}

	/**
	 * Determines access to the {@link T} object by evaluating if user has required
	 * permission using provided {@link PermissionEvaluator}.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@link T} object to check
	 * @return an {@link AuthorizationDecision}
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
		boolean granted = this.permissionEvaluator.hasPermission(authentication.get(), object, this.permission);
		return new AuthorizationDecision(granted);
	}

}
