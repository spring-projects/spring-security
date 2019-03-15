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

import java.util.List;

import org.springframework.expression.BeanResolver;
import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.OperatorOverloader;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypeComparator;
import org.springframework.expression.TypeConverter;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.TypedValue;

/**
 * An instance of {@link EvaluationContext} that delegates to another implementation.
 *
 * @author Rob Winch
 * @since 4.1
 */
class DelegatingEvaluationContext implements EvaluationContext {
	private final EvaluationContext delegate;

	public DelegatingEvaluationContext(EvaluationContext delegate) {
		super();
		this.delegate = delegate;
	}

	@Override
	public TypedValue getRootObject() {
		return this.delegate.getRootObject();
	}

	@Override
	public List<ConstructorResolver> getConstructorResolvers() {
		return this.delegate.getConstructorResolvers();
	}

	@Override
	public List<MethodResolver> getMethodResolvers() {
		return this.delegate.getMethodResolvers();
	}

	@Override
	public List<PropertyAccessor> getPropertyAccessors() {
		return this.delegate.getPropertyAccessors();
	}

	@Override
	public TypeLocator getTypeLocator() {
		return this.delegate.getTypeLocator();
	}

	@Override
	public TypeConverter getTypeConverter() {
		return this.delegate.getTypeConverter();
	}

	@Override
	public TypeComparator getTypeComparator() {
		return this.delegate.getTypeComparator();
	}

	@Override
	public OperatorOverloader getOperatorOverloader() {
		return this.delegate.getOperatorOverloader();
	}

	@Override
	public BeanResolver getBeanResolver() {
		return this.delegate.getBeanResolver();
	}

	@Override
	public void setVariable(String name, Object value) {
		this.delegate.setVariable(name, value);
	}

	@Override
	public Object lookupVariable(String name) {
		return this.delegate.lookupVariable(name);
	}
}
