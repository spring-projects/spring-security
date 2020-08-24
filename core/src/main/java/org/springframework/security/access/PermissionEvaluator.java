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

package org.springframework.security.access;

import java.io.Serializable;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.security.core.Authentication;

/**
 * Strategy used in expression evaluation to determine whether a user has a permission or
 * permissions for a given domain object.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface PermissionEvaluator extends AopInfrastructureBean {

	/**
	 * @param authentication represents the user in question. Should not be null.
	 * @param targetDomainObject the domain object for which permissions should be
	 * checked. May be null in which case implementations should return false, as the null
	 * condition can be checked explicitly in the expression.
	 * @param permission a representation of the permission object as supplied by the
	 * expression system. Not null.
	 * @return true if the permission is granted, false otherwise
	 */
	boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission);

	/**
	 * Alternative method for evaluating a permission where only the identifier of the
	 * target object is available, rather than the target instance itself.
	 * @param authentication represents the user in question. Should not be null.
	 * @param targetId the identifier for the object instance (usually a Long)
	 * @param targetType a String representing the target's type (usually a Java
	 * classname). Not null.
	 * @param permission a representation of the permission object as supplied by the
	 * expression system. Not null.
	 * @return true if the permission is granted, false otherwise
	 */
	boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission);

}
