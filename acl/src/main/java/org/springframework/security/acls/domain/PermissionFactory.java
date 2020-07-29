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

package org.springframework.security.acls.domain;

import java.util.List;

import org.springframework.security.acls.model.Permission;

/**
 * Provides a simple mechanism to retrieve {@link Permission} instances from integer
 * masks.
 *
 * @author Ben Alex
 * @since 2.0.3
 *
 */
public interface PermissionFactory {

	/**
	 * Dynamically creates a <code>CumulativePermission</code> or
	 * <code>BasePermission</code> representing the active bits in the passed mask.
	 * @param mask to build
	 * @return a Permission representing the requested object
	 */
	Permission buildFromMask(int mask);

	Permission buildFromName(String name);

	List<Permission> buildFromNames(List<String> names);

}
