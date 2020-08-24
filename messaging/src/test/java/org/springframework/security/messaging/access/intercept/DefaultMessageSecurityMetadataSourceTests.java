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

package org.springframework.security.messaging.access.intercept;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.messaging.Message;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.messaging.util.matcher.MessageMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;

@RunWith(MockitoJUnitRunner.class)
public class DefaultMessageSecurityMetadataSourceTests {

	@Mock
	MessageMatcher<Object> matcher1;

	@Mock
	MessageMatcher<Object> matcher2;

	@Mock
	Message<?> message;

	@Mock
	Authentication authentication;

	SecurityConfig config1;

	SecurityConfig config2;

	LinkedHashMap<MessageMatcher<?>, Collection<ConfigAttribute>> messageMap;

	MessageSecurityMetadataSource source;

	@Before
	public void setup() {
		this.messageMap = new LinkedHashMap<>();
		this.messageMap.put(this.matcher1, Arrays.<ConfigAttribute>asList(this.config1));
		this.messageMap.put(this.matcher2, Arrays.<ConfigAttribute>asList(this.config2));
		this.source = new DefaultMessageSecurityMetadataSource(this.messageMap);
	}

	@Test
	public void getAttributesNull() {
		assertThat(this.source.getAttributes(this.message)).isNull();
	}

	@Test
	public void getAttributesFirst() {
		given(this.matcher1.matches(this.message)).willReturn(true);
		assertThat(this.source.getAttributes(this.message)).containsOnly(this.config1);
	}

	@Test
	public void getAttributesSecond() {
		given(this.matcher1.matches(this.message)).willReturn(true);
		assertThat(this.source.getAttributes(this.message)).containsOnly(this.config2);
	}

	@Test
	public void getAllConfigAttributes() {
		assertThat(this.source.getAllConfigAttributes()).containsOnly(this.config1, this.config2);
	}

	@Test
	public void supportsFalse() {
		assertThat(this.source.supports(Object.class)).isFalse();
	}

	@Test
	public void supportsTrue() {
		assertThat(this.source.supports(Message.class)).isTrue();
	}

}
