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

import java.util.Collection;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.security.core.Authentication;

/**
 * Allows permissions to be pre-cached when using pre or post filtering with expressions
 *
 * @author Luke Taylor
 * @since 3.1
 */
public interface PermissionCacheOptimizer extends AopInfrastructureBean {

	/**
	 * Optimises the permission cache for anticipated operation on the supplied collection
	 * of objects. Usually this will entail batch loading of permissions for the objects
	 * in the collection.
	 * @param a the user for whom permissions should be obtained.
	 * @param objects the (non-null) collection of domain objects for which permissions
	 * should be retrieved.
	 */
	void cachePermissionsFor(Authentication a, Collection<?> objects);

}
