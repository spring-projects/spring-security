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

/**
 * @author Joe Scalise
 */
public class BusinessServiceImpl<E extends Entity> implements BusinessService {

	@Secured({ "ROLE_USER" })
	public void someUserMethod1() {
	}

	@Secured({ "ROLE_USER" })
	public void someUserMethod2() {
	}

	@Secured({ "ROLE_USER", "ROLE_ADMIN" })
	public void someUserAndAdminMethod() {
	}

	@Secured({ "ROLE_ADMIN" })
	public void someAdminMethod() {
	}

	public E someUserMethod3(final E entity) {
		return entity;
	}

	public int someOther(String s) {
		return 0;
	}

	public int someOther(int input) {
		return input;
	}

	public List<?> methodReturningAList(List<?> someList) {
		return someList;
	}

	public List<Object> methodReturningAList(String userName, String arg2) {
		return new ArrayList<>();
	}

	public Object[] methodReturningAnArray(Object[] someArray) {
		return null;
	}

	public void rolesAllowedUser() {

	}

}
