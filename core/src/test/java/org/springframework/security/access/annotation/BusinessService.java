/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.access.annotation;

import java.io.Serializable;
import java.util.List;

import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 */
@Secured({ "ROLE_USER" })
@PermitAll
public interface BusinessService extends Serializable {

	@Secured({ "ROLE_ADMIN" })
	@RolesAllowed({ "ROLE_ADMIN" })
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	void someAdminMethod();

	@Secured({ "ROLE_USER", "ROLE_ADMIN" })
	@RolesAllowed({ "ROLE_USER", "ROLE_ADMIN" })
	void someUserAndAdminMethod();

	@Secured({ "ROLE_USER" })
	@RolesAllowed({ "ROLE_USER" })
	void someUserMethod1();

	@Secured({ "ROLE_USER" })
	@RolesAllowed({ "ROLE_USER" })
	void someUserMethod2();

	@RolesAllowed({ "USER" })
	void rolesAllowedUser();

	int someOther(String s);

	int someOther(int input);

	List<?> methodReturningAList(List<?> someList);

	Object[] methodReturningAnArray(Object[] someArray);

	List<?> methodReturningAList(String userName, String extraParam);

	@RequireAdminRole
	@RequireUserRole
	default void repeatedAnnotations() {

	}

}
