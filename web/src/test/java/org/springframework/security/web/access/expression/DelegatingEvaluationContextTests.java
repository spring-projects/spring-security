/*
 * Copyright 2012-2016 the original author or authors.
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

package org.springframework.security.web.access.expression;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.expression.BeanResolver;
import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.OperatorOverloader;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypeComparator;
import org.springframework.expression.TypeConverter;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.TypedValue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class DelegatingEvaluationContextTests {

	@Mock
	DelegatingEvaluationContext delegate;

	@InjectMocks
	DelegatingEvaluationContext context;

	@Test
	public void getRootObject() {
		TypedValue expected = mock(TypedValue.class);
		given(this.delegate.getRootObject()).willReturn(expected);

		assertThat(this.context.getRootObject()).isEqualTo(expected);
	}

	@Test
	public void getConstructorResolvers() {
		List<ConstructorResolver> expected = new ArrayList<>();
		given(this.delegate.getConstructorResolvers()).willReturn(expected);

		assertThat(this.context.getConstructorResolvers()).isEqualTo(expected);
	}

	@Test
	public void getMethodResolvers() {
		List<MethodResolver> expected = new ArrayList<>();
		given(this.delegate.getMethodResolvers()).willReturn(expected);

		assertThat(this.context.getMethodResolvers()).isEqualTo(expected);
	}

	@Test
	public void getPropertyAccessors() {
		List<PropertyAccessor> expected = new ArrayList<>();
		given(this.delegate.getPropertyAccessors()).willReturn(expected);

		assertThat(this.context.getPropertyAccessors()).isEqualTo(expected);
	}

	@Test
	public void getTypeLocator() {

		TypeLocator expected = mock(TypeLocator.class);
		given(this.delegate.getTypeLocator()).willReturn(expected);

		assertThat(this.context.getTypeLocator()).isEqualTo(expected);
	}

	@Test
	public void getTypeConverter() {
		TypeConverter expected = mock(TypeConverter.class);
		given(this.delegate.getTypeConverter()).willReturn(expected);

		assertThat(this.context.getTypeConverter()).isEqualTo(expected);
	}

	@Test
	public void getTypeComparator() {
		TypeComparator expected = mock(TypeComparator.class);
		given(this.delegate.getTypeComparator()).willReturn(expected);

		assertThat(this.context.getTypeComparator()).isEqualTo(expected);
	}

	@Test
	public void getOperatorOverloader() {
		OperatorOverloader expected = mock(OperatorOverloader.class);
		given(this.delegate.getOperatorOverloader()).willReturn(expected);

		assertThat(this.context.getOperatorOverloader()).isEqualTo(expected);
	}

	@Test
	public void getBeanResolver() {
		BeanResolver expected = mock(BeanResolver.class);
		given(this.delegate.getBeanResolver()).willReturn(expected);

		assertThat(this.context.getBeanResolver()).isEqualTo(expected);
	}

	@Test
	public void setVariable() {
		String name = "name";
		String value = "value";

		this.context.setVariable(name, value);

		verify(this.delegate).setVariable(name, value);
	}

	@Test
	public void lookupVariable() {
		String name = "name";
		String expected = "expected";
		given(this.delegate.lookupVariable(name)).willReturn(expected);

		assertThat(this.context.lookupVariable(name)).isEqualTo(expected);
	}

}
