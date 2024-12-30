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

package org.springframework.security.config.annotation.web;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AbstractConfiguredSecurityBuilder}.
 *
 * @author Joe Grandja
 */
public class AbstractConfiguredSecurityBuilderTests {

	private TestConfiguredSecurityBuilder builder;

	@BeforeEach
	public void setUp() {
		this.builder = new TestConfiguredSecurityBuilder(mock(ObjectPostProcessor.class));
	}

	@Test
	public void constructorWhenObjectPostProcessorIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new TestConfiguredSecurityBuilder(null));
	}

	@Test
	public void objectPostProcessorWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.builder.objectPostProcessor(null));
	}

	@Test
	public void applyWhenDuplicateConfigurerAddedThenDuplicateConfigurerRemoved() throws Exception {
		this.builder.apply(new TestSecurityConfigurer());
		this.builder.apply(new TestSecurityConfigurer());
		assertThat(this.builder.getConfigurers(TestSecurityConfigurer.class)).hasSize(1);
	}

	@Test
	public void buildWhenBuildTwiceThenThrowIllegalStateException() throws Exception {
		this.builder.build();
		assertThatIllegalStateException().isThrownBy(() -> this.builder.build());
	}

	@Test
	public void getObjectWhenNotBuiltThenThrowIllegalStateException() {
		assertThatIllegalStateException().isThrownBy(this.builder::getObject);
	}

	@Test
	public void buildWhenConfigurerAppliesAnotherConfigurerThenObjectStillBuilds() throws Exception {
		DelegateSecurityConfigurer.CONFIGURER = mock(SecurityConfigurer.class);
		this.builder.apply(new DelegateSecurityConfigurer());
		this.builder.build();
		verify(DelegateSecurityConfigurer.CONFIGURER).init(this.builder);
		verify(DelegateSecurityConfigurer.CONFIGURER).configure(this.builder);
	}

	@Test
	public void buildWhenConfigurerAppliesAndRemoveAnotherConfigurerThenNotConfigured() throws Exception {
		ApplyAndRemoveSecurityConfigurer.CONFIGURER = mock(SecurityConfigurer.class);
		this.builder.apply(new ApplyAndRemoveSecurityConfigurer());
		this.builder.build();
		verify(ApplyAndRemoveSecurityConfigurer.CONFIGURER, never()).init(this.builder);
		verify(ApplyAndRemoveSecurityConfigurer.CONFIGURER, never()).configure(this.builder);
	}

	@Test
	public void buildWhenConfigurerAppliesAndRemoveAnotherConfigurersThenNotConfigured() throws Exception {
		ApplyAndRemoveAllSecurityConfigurer.CONFIGURER = mock(SecurityConfigurer.class);
		this.builder.apply(new ApplyAndRemoveAllSecurityConfigurer());
		this.builder.build();
		verify(ApplyAndRemoveAllSecurityConfigurer.CONFIGURER, never()).init(this.builder);
		verify(ApplyAndRemoveAllSecurityConfigurer.CONFIGURER, never()).configure(this.builder);
	}

	@Test
	public void getConfigurerWhenMultipleConfigurersThenThrowIllegalStateException() throws Exception {
		TestConfiguredSecurityBuilder builder = new TestConfiguredSecurityBuilder(mock(ObjectPostProcessor.class),
				true);
		builder.apply(new DelegateSecurityConfigurer());
		builder.apply(new DelegateSecurityConfigurer());
		assertThatIllegalStateException().isThrownBy(() -> builder.getConfigurer(DelegateSecurityConfigurer.class));
	}

	@Test
	public void removeConfigurerWhenMultipleConfigurersThenThrowIllegalStateException() throws Exception {
		TestConfiguredSecurityBuilder builder = new TestConfiguredSecurityBuilder(mock(ObjectPostProcessor.class),
				true);
		builder.apply(new DelegateSecurityConfigurer());
		builder.apply(new DelegateSecurityConfigurer());
		assertThatIllegalStateException().isThrownBy(() -> builder.removeConfigurer(DelegateSecurityConfigurer.class));
	}

	@Test
	public void removeConfigurersWhenMultipleConfigurersThenConfigurersRemoved() throws Exception {
		DelegateSecurityConfigurer configurer1 = new DelegateSecurityConfigurer();
		DelegateSecurityConfigurer configurer2 = new DelegateSecurityConfigurer();
		TestConfiguredSecurityBuilder builder = new TestConfiguredSecurityBuilder(mock(ObjectPostProcessor.class),
				true);
		builder.apply(configurer1);
		builder.apply(configurer2);
		List<DelegateSecurityConfigurer> removedConfigurers = builder
			.removeConfigurers(DelegateSecurityConfigurer.class);
		assertThat(removedConfigurers).hasSize(2);
		assertThat(removedConfigurers).containsExactly(configurer1, configurer2);
		assertThat(builder.getConfigurers(DelegateSecurityConfigurer.class)).isEmpty();
	}

	@Test
	public void getConfigurersWhenMultipleConfigurersThenConfigurersReturned() throws Exception {
		DelegateSecurityConfigurer configurer1 = new DelegateSecurityConfigurer();
		DelegateSecurityConfigurer configurer2 = new DelegateSecurityConfigurer();
		TestConfiguredSecurityBuilder builder = new TestConfiguredSecurityBuilder(mock(ObjectPostProcessor.class),
				true);
		builder.apply(configurer1);
		builder.apply(configurer2);
		List<DelegateSecurityConfigurer> configurers = builder.getConfigurers(DelegateSecurityConfigurer.class);
		assertThat(configurers).hasSize(2);
		assertThat(configurers).containsExactly(configurer1, configurer2);
		assertThat(builder.getConfigurers(DelegateSecurityConfigurer.class)).hasSize(2);
	}

	@Test
	public void withWhenConfigurerThenConfigurerAdded() throws Exception {
		this.builder.with(new TestSecurityConfigurer(), Customizer.withDefaults());
		assertThat(this.builder.getConfigurers(TestSecurityConfigurer.class)).hasSize(1);
	}

	@Test
	public void withWhenDuplicateConfigurerAddedThenDuplicateConfigurerRemoved() throws Exception {
		this.builder.with(new TestSecurityConfigurer(), Customizer.withDefaults());
		this.builder.with(new TestSecurityConfigurer(), Customizer.withDefaults());
		assertThat(this.builder.getConfigurers(TestSecurityConfigurer.class)).hasSize(1);
	}

	private static class ApplyAndRemoveSecurityConfigurer
			extends SecurityConfigurerAdapter<Object, TestConfiguredSecurityBuilder> {

		private static SecurityConfigurer<Object, TestConfiguredSecurityBuilder> CONFIGURER;

		@Override
		public void init(TestConfiguredSecurityBuilder builder) throws Exception {
			builder.apply(CONFIGURER);
			builder.removeConfigurer(CONFIGURER.getClass());
		}

	}

	private static class ApplyAndRemoveAllSecurityConfigurer
			extends SecurityConfigurerAdapter<Object, TestConfiguredSecurityBuilder> {

		private static SecurityConfigurer<Object, TestConfiguredSecurityBuilder> CONFIGURER;

		@Override
		public void init(TestConfiguredSecurityBuilder builder) throws Exception {
			builder.apply(CONFIGURER);
			builder.removeConfigurers(CONFIGURER.getClass());
		}

	}

	private static class DelegateSecurityConfigurer
			extends SecurityConfigurerAdapter<Object, TestConfiguredSecurityBuilder> {

		private static SecurityConfigurer<Object, TestConfiguredSecurityBuilder> CONFIGURER;

		@Override
		public void init(TestConfiguredSecurityBuilder builder) throws Exception {
			builder.apply(CONFIGURER);
		}

	}

	private static class TestSecurityConfigurer
			extends SecurityConfigurerAdapter<Object, TestConfiguredSecurityBuilder> {

	}

	private static final class TestConfiguredSecurityBuilder
			extends AbstractConfiguredSecurityBuilder<Object, TestConfiguredSecurityBuilder> {

		private TestConfiguredSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
			super(objectPostProcessor);
		}

		private TestConfiguredSecurityBuilder(ObjectPostProcessor<Object> objectPostProcessor,
				boolean allowConfigurersOfSameType) {
			super(objectPostProcessor, allowConfigurersOfSameType);
		}

		@Override
		public Object performBuild() {
			return "success";
		}

	}

}
