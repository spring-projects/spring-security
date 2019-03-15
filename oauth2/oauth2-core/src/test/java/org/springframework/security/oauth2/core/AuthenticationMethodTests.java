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
package org.springframework.security.oauth2.core;

import static org.assertj.core.api.Assertions.*;

import org.junit.Test;

/**
 * Tests for {@link AuthenticationMethod}.
 *
 * @author MyeongHyeon Lee
 */
public class AuthenticationMethodTests {

	@Test
	public void constructorWhenValueIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new AuthenticationMethod(null)).hasMessage("value cannot be empty");
	}

	@Test
	public void getValueWhenHeaderAuthenticationTypeThenReturnHeader() {
		assertThat(AuthenticationMethod.HEADER.getValue()).isEqualTo("header");
	}

	@Test
	public void getValueWhenFormAuthenticationTypeThenReturnForm() {
		assertThat(AuthenticationMethod.FORM.getValue()).isEqualTo("form");
	}

	@Test
	public void getValueWhenFormAuthenticationTypeThenReturnQuery() {
		assertThat(AuthenticationMethod.QUERY.getValue()).isEqualTo("query");
	}
}
