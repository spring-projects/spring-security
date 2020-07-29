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

package org.springframework.security.access.annotation;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

/**
 * @author Luke Taylor
 */
@PermitAll
public class Jsr250BusinessServiceImpl implements BusinessService {

	@Override
	@RolesAllowed("ROLE_USER")
	public void someUserMethod1() {
	}

	@Override
	@RolesAllowed("ROLE_USER")
	public void someUserMethod2() {
	}

	@Override
	@RolesAllowed({ "ROLE_USER", "ROLE_ADMIN" })
	public void someUserAndAdminMethod() {
	}

	@Override
	@RolesAllowed("ROLE_ADMIN")
	public void someAdminMethod() {
	}

	@Override
	public int someOther(String input) {
		return 0;
	}

	@Override
	public int someOther(int input) {
		return input;
	}

	@Override
	public List<?> methodReturningAList(List<?> someList) {
		return someList;
	}

	@Override
	public List<?> methodReturningAList(String userName, String arg2) {
		return new ArrayList<>();
	}

	@Override
	public Object[] methodReturningAnArray(Object[] someArray) {
		return null;
	}

	@Override
	@RolesAllowed({ "USER" })
	public void rolesAllowedUser() {

	}

}
