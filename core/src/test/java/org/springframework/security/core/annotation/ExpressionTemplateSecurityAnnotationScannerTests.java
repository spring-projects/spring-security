/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.core.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.access.prepost.PreAuthorize;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ExpressionTemplateSecurityAnnotationScanner}
 *
 * @author DingHao
 */
public class ExpressionTemplateSecurityAnnotationScannerTests {

	private ExpressionTemplateSecurityAnnotationScanner<PreAuthorize> scanner = new ExpressionTemplateSecurityAnnotationScanner<>(
			PreAuthorize.class, new AnnotationTemplateExpressionDefaults());

	@Test
	void parseMultipleMetaSourceAnnotationParameter() throws Exception {
		Method method = MessageService.class.getDeclaredMethod("sayHello", String.class);
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("check(#name)");
	}

	@Test
	void parseMultipleMetaSourceAnnotationParameterWithAliasFor() throws Exception {
		Method method = MessageService.class.getDeclaredMethod("save", String.class);
		PreAuthorize preAuthorize = this.scanner.scan(method, method.getDeclaringClass());
		assertThat(preAuthorize.value()).isEqualTo("check(#name)");
	}

	@Documented
	@Retention(RetentionPolicy.RUNTIME)
	@Target({ ElementType.TYPE, ElementType.METHOD })
	@PreAuthorize("check({object})")
	@interface HasPermission {

		String object();

	}

	@Documented
	@Retention(RetentionPolicy.RUNTIME)
	@Target({ ElementType.TYPE, ElementType.METHOD })
	@HasPermission(object = "{value}")
	@interface HasReadPermission {

		String value();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@Target({ ElementType.TYPE, ElementType.METHOD })
	@HasPermission(object = "{value}")
	@interface HasWritePermission {

		@AliasFor(annotation = HasPermission.class, value = "object")
		String value();

	}

	private interface MessageService {

		@HasReadPermission("#name")
		String sayHello(String name);

		@HasWritePermission("#name")
		void save(String name);

	}

}
