/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.access.expression.method;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.aopalliance.intercept.MethodInvocation;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.TypedValue;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
public class DefaultMethodSecurityExpressionHandlerTests {

	private DefaultMethodSecurityExpressionHandler handler;

	@Mock
	private Authentication authentication;

	@Mock
	private MethodInvocation methodInvocation;

	@Mock
	private AuthenticationTrustResolver trustResolver;

	@BeforeEach
	public void setup() {
		this.handler = new DefaultMethodSecurityExpressionHandler();
	}

	private void setupMocks() {
		given(this.methodInvocation.getThis()).willReturn(new Foo());
		given(this.methodInvocation.getMethod()).willReturn(Foo.class.getMethods()[0]);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void setTrustResolverNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setTrustResolver(null));
	}

	@Test
	public void createEvaluationContextCustomTrustResolver() {
		setupMocks();
		this.handler.setTrustResolver(this.trustResolver);
		Expression expression = this.handler.getExpressionParser().parseExpression("anonymous");
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.methodInvocation);
		expression.getValue(context, Boolean.class);
		verify(this.trustResolver).isAnonymous(this.authentication);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void filterByKeyWhenUsingMapThenFiltersMap() {
		setupMocks();
		final Map<String, String> map = new HashMap<>();
		map.put("key1", "value1");
		map.put("key2", "value2");
		map.put("key3", "value3");
		Expression expression = this.handler.getExpressionParser().parseExpression("filterObject.key eq 'key2'");
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.methodInvocation);
		Object filtered = this.handler.filter(map, expression, context);
		assertThat(filtered == map);
		Map<String, String> result = ((Map<String, String>) filtered);
		assertThat(result.size() == 1);
		assertThat(result).containsKey("key2");
		assertThat(result).containsValue("value2");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void filterByValueWhenUsingMapThenFiltersMap() {
		setupMocks();
		final Map<String, String> map = new HashMap<>();
		map.put("key1", "value1");
		map.put("key2", "value2");
		map.put("key3", "value3");
		Expression expression = this.handler.getExpressionParser().parseExpression("filterObject.value eq 'value3'");
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.methodInvocation);
		Object filtered = this.handler.filter(map, expression, context);
		assertThat(filtered == map);
		Map<String, String> result = ((Map<String, String>) filtered);
		assertThat(result.size() == 1);
		assertThat(result).containsKey("key3");
		assertThat(result).containsValue("value3");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void filterByKeyAndValueWhenUsingMapThenFiltersMap() {
		setupMocks();
		final Map<String, String> map = new HashMap<>();
		map.put("key1", "value1");
		map.put("key2", "value2");
		map.put("key3", "value3");
		Expression expression = this.handler.getExpressionParser()
				.parseExpression("(filterObject.key eq 'key1') or (filterObject.value eq 'value2')");
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.methodInvocation);
		Object filtered = this.handler.filter(map, expression, context);
		assertThat(filtered == map);
		Map<String, String> result = ((Map<String, String>) filtered);
		assertThat(result.size() == 2);
		assertThat(result).containsKeys("key1", "key2");
		assertThat(result).containsValues("value1", "value2");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void filterWhenUsingStreamThenFiltersStream() {
		setupMocks();
		final Stream<String> stream = Stream.of("1", "2", "3");
		Expression expression = this.handler.getExpressionParser().parseExpression("filterObject ne '2'");
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.methodInvocation);
		Object filtered = this.handler.filter(stream, expression, context);
		assertThat(filtered).isInstanceOf(Stream.class);
		List<String> list = ((Stream<String>) filtered).collect(Collectors.toList());
		assertThat(list).containsExactly("1", "3");
	}

	@Test
	public void filterStreamWhenClosedThenUpstreamGetsClosed() {
		setupMocks();
		final Stream<?> upstream = mock(Stream.class);
		doReturn(Stream.<String>empty()).when(upstream).filter(any());
		Expression expression = this.handler.getExpressionParser().parseExpression("true");
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.methodInvocation);
		((Stream) this.handler.filter(upstream, expression, context)).close();
		verify(upstream).close();
	}

	@Test
	public void createEvaluationContextSupplierAuthentication() {
		setupMocks();
		Supplier<Authentication> mockAuthenticationSupplier = mock(Supplier.class);
		given(mockAuthenticationSupplier.get()).willReturn(this.authentication);
		EvaluationContext context = this.handler.createEvaluationContext(mockAuthenticationSupplier,
				this.methodInvocation);
		verifyNoInteractions(mockAuthenticationSupplier);
		assertThat(context.getRootObject()).extracting(TypedValue::getValue)
				.asInstanceOf(InstanceOfAssertFactories.type(MethodSecurityExpressionRoot.class))
				.extracting(SecurityExpressionRoot::getAuthentication).isEqualTo(this.authentication);
		verify(mockAuthenticationSupplier).get();
	}

	static class Foo {

		void bar() {
		}

	}

}
