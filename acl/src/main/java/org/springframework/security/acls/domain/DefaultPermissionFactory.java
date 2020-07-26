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
package org.springframework.security.acls.domain;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.acls.model.Permission;
import org.springframework.util.Assert;

/**
 * Default implementation of {@link PermissionFactory}.
 * <p>
 * Used as a strategy by classes which wish to map integer masks and permission names to
 * <tt>Permission</tt> instances for use with the ACL implementation.
 * <p>
 * Maintains a registry of permission names and masks to <tt>Permission</tt> instances.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @since 2.0.3
 */
public class DefaultPermissionFactory implements PermissionFactory {

	private final Map<Integer, Permission> registeredPermissionsByInteger = new HashMap<>();

	private final Map<String, Permission> registeredPermissionsByName = new HashMap<>();

	/**
	 * Registers the <tt>Permission</tt> fields from the <tt>BasePermission</tt> class.
	 */
	public DefaultPermissionFactory() {
		registerPublicPermissions(BasePermission.class);
	}

	/**
	 * Registers the <tt>Permission</tt> fields from the supplied class.
	 */
	public DefaultPermissionFactory(Class<? extends Permission> permissionClass) {
		registerPublicPermissions(permissionClass);
	}

	/**
	 * Registers a map of named <tt>Permission</tt> instances.
	 * @param namedPermissions the map of <tt>Permission</tt>s, keyed by name.
	 */
	public DefaultPermissionFactory(Map<String, ? extends Permission> namedPermissions) {
		for (String name : namedPermissions.keySet()) {
			registerPermission(namedPermissions.get(name), name);
		}
	}

	/**
	 * Registers the public static fields of type {@link Permission} for a give class.
	 * <p>
	 * These permissions will be registered under the name of the field. See
	 * {@link BasePermission} for an example.
	 * @param clazz a {@link Permission} class with public static fields to register
	 */
	protected void registerPublicPermissions(Class<? extends Permission> clazz) {
		Assert.notNull(clazz, "Class required");

		Field[] fields = clazz.getFields();

		for (Field field : fields) {
			try {
				Object fieldValue = field.get(null);

				if (Permission.class.isAssignableFrom(fieldValue.getClass())) {
					// Found a Permission static field
					Permission perm = (Permission) fieldValue;
					String permissionName = field.getName();

					registerPermission(perm, permissionName);
				}
			}
			catch (Exception ignore) {
			}
		}
	}

	protected void registerPermission(Permission perm, String permissionName) {
		Assert.notNull(perm, "Permission required");
		Assert.hasText(permissionName, "Permission name required");

		Integer mask = perm.getMask();

		// Ensure no existing Permission uses this integer or code
		Assert.isTrue(!this.registeredPermissionsByInteger.containsKey(mask),
				() -> "An existing Permission already provides mask " + mask);
		Assert.isTrue(!this.registeredPermissionsByName.containsKey(permissionName),
				() -> "An existing Permission already provides name '" + permissionName + "'");

		// Register the new Permission
		this.registeredPermissionsByInteger.put(mask, perm);
		this.registeredPermissionsByName.put(permissionName, perm);
	}

	@Override
	public Permission buildFromMask(int mask) {
		if (this.registeredPermissionsByInteger.containsKey(mask)) {
			// The requested mask has an exact match against a statically-defined
			// Permission, so return it
			return this.registeredPermissionsByInteger.get(mask);
		}

		// To get this far, we have to use a CumulativePermission
		CumulativePermission permission = new CumulativePermission();

		for (int i = 0; i < 32; i++) {
			int permissionToCheck = 1 << i;

			if ((mask & permissionToCheck) == permissionToCheck) {
				Permission p = this.registeredPermissionsByInteger.get(permissionToCheck);

				if (p == null) {
					throw new IllegalStateException(
							"Mask '" + permissionToCheck + "' does not have a corresponding static Permission");
				}
				permission.set(p);
			}
		}

		return permission;
	}

	@Override
	public Permission buildFromName(String name) {
		Permission p = this.registeredPermissionsByName.get(name);

		if (p == null) {
			throw new IllegalArgumentException("Unknown permission '" + name + "'");
		}

		return p;
	}

	@Override
	public List<Permission> buildFromNames(List<String> names) {
		if ((names == null) || (names.size() == 0)) {
			return Collections.emptyList();
		}

		List<Permission> permissions = new ArrayList<>(names.size());

		for (String name : names) {
			permissions.add(buildFromName(name));
		}

		return permissions;
	}

}
