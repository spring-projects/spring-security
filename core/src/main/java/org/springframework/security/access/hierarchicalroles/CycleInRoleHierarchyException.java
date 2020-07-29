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

package org.springframework.security.access.hierarchicalroles;

/**
 * Exception that is thrown because of a cycle in the role hierarchy definition
 *
 * @author Michael Mayr
 */
public class CycleInRoleHierarchyException extends RuntimeException {

	private static final long serialVersionUID = -4970510612118296707L;

	public CycleInRoleHierarchyException() {
		super("Exception thrown because of a cycle in the role hierarchy definition!");
	}

}
