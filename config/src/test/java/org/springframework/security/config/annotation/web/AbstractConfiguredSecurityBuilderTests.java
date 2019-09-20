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
package org.springframework.security.config.annotation.web;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AbstractConfiguredSecurityBuilder}.
 *
 * @author Joe Grandja
 */
public class AbstractConfiguredSecurityBuilderTests {
	private TestConfiguredSecurityBuilder builder;

	@Before
	public void setUp() {
		this.builder = new TestConfiguredSecurityBuilder(mock(ObjectPostProcessor.class));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenObjectPostProcessorIsNullThenThrowIllegalArgumentException() {
		new TestConfiguredSecurityBuilder(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void objectPostProcessorWhenNullThenThrowIllegalArgumentException() {
		this.builder.objectPostProcessor(null);
	}

	@Test
	public void applyWhenDuplicateConfigurerAddedThenDuplicateConfigurerRemoved() throws Exception {
		this.builder.apply(new TestSecurityConfigurer());
		this.builder.apply(new TestSecurityConfigurer());
		assertThat(this.builder.getConfigurers(TestSecurityConfigurer.class)).hasSize(1);
	}

	@Test(expected = IllegalStateException.class)
	public void buildWhenBuildTwiceThenThrowIllegalStateException() throws Exception {
		this.builder.build();
		this.builder.build();
	}

	@Test(expected = IllegalStateException.class)
	public void getObjectWhenNotBuiltThenThrowIllegalStateException() {
		this.builder.getObject();
	}

	@Test
	public void buildWhenConfigurerAppliesAnotherConfigurerThenObjectStillBuilds() throws Exception {
		DelegateSecurityConfigurer.CONFIGURER = mock(SecurityConfigurer.class);
		this.builder.apply(new DelegateSecurityConfigurer());
		this.builder.build();
		verify(DelegateSecurityConfigurer.CONFIGURER).init(this.builder);
		verify(DelegateSecurityConfigurer.CONFIGURER).configure(this.builder);
	}

	@Test(expected = IllegalStateException.class)
	public void getConfigurerWhenMultipleConfigurersThenThrowIllegalStateException() throws Exception {
		TestConfiguredSecurityBuilder builder = new TestConfiguredSecurityBuilder(mock(ObjectPostProcessor.class), true);
		builder.apply(new DelegateSecurityConfigurer());
		builder.apply(new DelegateSecurityConfigurer());
		builder.getConfigurer(DelegateSecurityConfigurer.class);
	}

	@Test(expected = IllegalStateException.class)
	public void removeConfigurerWhenMultipleConfigurersThenThrowIllegalStateException() throws Exception {
		TestConfiguredSecurityBuilder builder = new TestConfiguredSecurityBuilder(mock(ObjectPostProcessor.class), true);
		builder.apply(new DelegateSecurityConfigurer());
		builder.apply(new DelegateSecurityConfigurer());
		builder.removeConfigurer(DelegateSecurityConfigurer.class);
	}

	@Test
	public void removeConfigurersWhenMultipleConfigurersThenConfigurersRemoved() throws Exception {
		DelegateSecurityConfigurer configurer1 = new DelegateSecurityConfigurer();
		DelegateSecurityConfigurer configurer2 = new DelegateSecurityConfigurer();
		TestConfiguredSecurityBuilder builder = new TestConfiguredSecurityBuilder(mock(ObjectPostProcessor.class), true);
		builder.apply(configurer1);
		builder.apply(configurer2);
		List<DelegateSecurityConfigurer> removedConfigurers = builder.removeConfigurers(DelegateSecurityConfigurer.class);
		assertThat(removedConfigurers).hasSize(2);
		assertThat(removedConfigurers).containsExactly(configurer1, configurer2);
		assertThat(builder.getConfigurers(DelegateSecurityConfigurer.class)).isEmpty();
	}

	@Test
	public void getConfigurersWhenMultipleConfigurersThenConfigurersReturned() throws Exception {
		DelegateSecurityConfigurer configurer1 = new DelegateSecurityConfigurer();
		DelegateSecurityConfigurer configurer2 = new DelegateSecurityConfigurer();
		TestConfiguredSecurityBuilder builder = new TestConfiguredSecurityBuilder(mock(ObjectPostProcessor.class), true);
		builder.apply(configurer1);
		builder.apply(configurer2);
		List<DelegateSecurityConfigurer> configurers = builder.getConfigurers(DelegateSecurityConfigurer.class);
		assertThat(configurers).hasSize(2);
		assertThat(configurers).containsExactly(configurer1, configurer2);
		assertThat(builder.getConfigurers(DelegateSecurityConfigurer.class)).hasSize(2);
	}

	private static class DelegateSecurityConfigurer extends SecurityConfigurerAdapter<Object, TestConfiguredSecurityBuilder> {
		private static SecurityConfigurer<Object, TestConfiguredSecurityBuilder> CONFIGURER;

		@Override
		public void init(TestConfiguredSecurityBuilder builder) throws Exception {
			builder.apply(CONFIGURER);
		}
	}

	private static class TestSecurityConfigurer extends SecurityConfigurerAdapter<Object, TestConfiguredSecurityBuilder> { }

	private static class TestConfiguredSecurityBuilder extends AbstractConfiguredSecurityBuilder<Object, TestConfiguredSecurityBuilder> {

		private TestConfiguredSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
			super(objectPostProcessor);
		}

		private TestConfiguredSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor, boolean allowConfigurersOfSameType) {
			super(objectPostProcessor, allowConfigurersOfSameType);
		}

		public Object performBuild() {
			return "success";
		}
	}
}
