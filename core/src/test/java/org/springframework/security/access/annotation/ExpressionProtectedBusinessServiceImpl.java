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

import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;

public class ExpressionProtectedBusinessServiceImpl implements BusinessService {

	@Override
	public void someAdminMethod() {
	}

	@Override
	public int someOther(String s) {
		return 0;
	}

	@Override
	public int someOther(int input) {
		return 0;
	}

	@Override
	public void someUserAndAdminMethod() {
	}

	@Override
	public void someUserMethod1() {
	}

	@Override
	public void someUserMethod2() {
	}

	@Override
	@PreFilter(filterTarget = "someList", value = "filterObject == authentication.name or filterObject == 'sam'")
	@PostFilter("filterObject == 'bob'")
	public List<?> methodReturningAList(List<?> someList) {
		return someList;
	}

	@Override
	public List<Object> methodReturningAList(String userName, String arg2) {
		return new ArrayList<>();
	}

	@Override
	@PostFilter("filterObject == 'bob'")
	public Object[] methodReturningAnArray(Object[] someArray) {
		return someArray;
	}

	@PreAuthorize("#x == 'x' and @number.intValue() == 1294 ")
	public void methodWithBeanNamePropertyAccessExpression(String x) {
	}

	@Override
	public void rolesAllowedUser() {
	}

}
