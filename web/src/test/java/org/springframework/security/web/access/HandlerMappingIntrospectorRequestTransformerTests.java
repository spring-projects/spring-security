/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.access;

import java.util.Collections;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
class HandlerMappingIntrospectorRequestTransformerTests {

	@Mock
	HandlerMappingIntrospector hmi;

	HandlerMappingIntrospectorRequestTransformer transformer;

	@BeforeEach
	void setup() {
		this.transformer = new HandlerMappingIntrospectorRequestTransformer(this.hmi);
	}

	@Test
	void constructorWhenHmiIsNullThenIllegalArgumentException() {
		AssertionsForClassTypes.assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new HandlerMappingIntrospectorRequestTransformer(null));
	}

	@Test
	void transformThenNewRequestPassedToSetCache() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		HttpServletRequest transformedRequest = this.transformer.transform(request);

		ArgumentCaptor<HttpServletRequest> requestArg = ArgumentCaptor.forClass(HttpServletRequest.class);
		verify(this.hmi).setCache(requestArg.capture());
		assertThat(transformedRequest).isNotEqualTo(request);
	}

	@Test
	void transformThenResultPassedToSetCache() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		HttpServletRequest transformedRequest = this.transformer.transform(request);

		ArgumentCaptor<HttpServletRequest> requestArg = ArgumentCaptor.forClass(HttpServletRequest.class);
		verify(this.hmi).setCache(requestArg.capture());
		assertThat(requestArg.getValue()).isEqualTo(transformedRequest);
	}

	/**
	 * The request passed into the transformer does not allow interactions on certain
	 * methods, we need to ensure that the methods used by
	 * {@link HandlerMappingIntrospector#setCache(HttpServletRequest)} are overridden.
	 */
	@Test
	void transformThenResultDoesNotDelegateToSetAttribute() {
		HttpServletRequest request = mock(HttpServletRequest.class);

		this.transformer.transform(request);

		ArgumentCaptor<HttpServletRequest> requestArg = ArgumentCaptor.forClass(HttpServletRequest.class);
		verify(this.hmi).setCache(requestArg.capture());
		HttpServletRequest transformedRequest = requestArg.getValue();
		String attrName = "any";
		String attrValue = "value";
		transformedRequest.setAttribute(attrName, attrValue);
		verifyNoInteractions(request);
		assertThat(transformedRequest.getAttribute(attrName)).isEqualTo(attrValue);
	}

	@Test
	void transformThenSetAttributeWorks() {
		HttpServletRequest request = mock(HttpServletRequest.class);

		this.transformer.transform(request);

		ArgumentCaptor<HttpServletRequest> requestArg = ArgumentCaptor.forClass(HttpServletRequest.class);
		verify(this.hmi).setCache(requestArg.capture());
		HttpServletRequest transformedRequest = requestArg.getValue();
		String attrName = "any";
		String attrValue = "value";
		transformedRequest.setAttribute(attrName, attrValue);
		assertThat(transformedRequest.getAttribute(attrName)).isEqualTo(attrValue);
	}

	/**
	 * The request passed into the transformer does not allow interactions on certain
	 * methods, we need to ensure that the methods used by
	 * {@link HandlerMappingIntrospector#setCache(HttpServletRequest)} are overridden.
	 */
	@Test
	void transformThenResultDoesNotDelegateToGetAttribute() {
		HttpServletRequest request = mock(HttpServletRequest.class);

		this.transformer.transform(request);

		ArgumentCaptor<HttpServletRequest> requestArg = ArgumentCaptor.forClass(HttpServletRequest.class);
		verify(this.hmi).setCache(requestArg.capture());
		HttpServletRequest transformedRequest = requestArg.getValue();
		transformedRequest.getAttribute("any");
		verifyNoInteractions(request);
	}

	/**
	 * The request passed into the transformer does not allow interactions on certain
	 * methods, we need to ensure that the methods used by
	 * {@link HandlerMappingIntrospector#setCache(HttpServletRequest)} are overridden.
	 */
	@Test
	void transformThenResultDoesNotDelegateToGetAttributeNames() {
		HttpServletRequest request = mock(HttpServletRequest.class);

		this.transformer.transform(request);

		ArgumentCaptor<HttpServletRequest> requestArg = ArgumentCaptor.forClass(HttpServletRequest.class);
		verify(this.hmi).setCache(requestArg.capture());
		HttpServletRequest transformedRequest = requestArg.getValue();
		transformedRequest.getAttributeNames();
		verifyNoInteractions(request);
	}

	@Test
	void transformThenGetAttributeNamesWorks() {
		HttpServletRequest request = mock(HttpServletRequest.class);

		this.transformer.transform(request);

		ArgumentCaptor<HttpServletRequest> requestArg = ArgumentCaptor.forClass(HttpServletRequest.class);
		verify(this.hmi).setCache(requestArg.capture());
		HttpServletRequest transformedRequest = requestArg.getValue();
		String attrName = "any";
		String attrValue = "value";
		transformedRequest.setAttribute(attrName, attrValue);
		assertThat(Collections.list(transformedRequest.getAttributeNames())).containsExactly(attrName);
	}

	/**
	 * The request passed into the transformer does not allow interactions on certain
	 * methods, we need to ensure that the methods used by
	 * {@link HandlerMappingIntrospector#setCache(HttpServletRequest)} are overridden.
	 */
	@Test
	void transformThenResultDoesNotDelegateToRemoveAttribute() {
		HttpServletRequest request = mock(HttpServletRequest.class);

		this.transformer.transform(request);

		ArgumentCaptor<HttpServletRequest> requestArg = ArgumentCaptor.forClass(HttpServletRequest.class);
		verify(this.hmi).setCache(requestArg.capture());
		HttpServletRequest transformedRequest = requestArg.getValue();
		transformedRequest.removeAttribute("any");
		verifyNoInteractions(request);
	}

	/**
	 * The request passed into the transformer does not allow interactions on certain
	 * methods, we need to ensure that the methods used by
	 * {@link HandlerMappingIntrospector#setCache(HttpServletRequest)} are overridden.
	 */
	@Test
	void transformThenResultDoesNotDelegateToGetDispatcherType() {
		HttpServletRequest request = mock(HttpServletRequest.class);

		this.transformer.transform(request);

		ArgumentCaptor<HttpServletRequest> requestArg = ArgumentCaptor.forClass(HttpServletRequest.class);
		verify(this.hmi).setCache(requestArg.capture());
		HttpServletRequest transformedRequest = requestArg.getValue();
		assertThat(transformedRequest.getDispatcherType()).isEqualTo(DispatcherType.REQUEST);
		verifyNoInteractions(request);
	}

}
