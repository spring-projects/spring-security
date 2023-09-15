/*
 * Copyright 2019-2023 the original author or authors.
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

package org.springframework.gradle.xsd;

import org.junit.jupiter.api.Test;
import org.springframework.gradle.xsd.CreateVersionlessXsdTask.MajorMinorVersion;
import org.springframework.gradle.xsd.CreateVersionlessXsdTask.XsdFileMajorMinorVersion;

import java.io.File;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

/**
 * @author Rob Winch
 */
class CreateVersionlessXsdTaskTests {

	@Test
	void xsdCreateWhenValid() {
		File file = new File("spring-security-2.0.xsd");
		XsdFileMajorMinorVersion xsdFile = XsdFileMajorMinorVersion.create(file);
		assertThat(xsdFile).isNotNull();
		assertThat(xsdFile.getFile()).isEqualTo(file);
		assertThat(xsdFile.getVersion().getMajor()).isEqualTo(2);
		assertThat(xsdFile.getVersion().getMinor()).isEqualTo(0);
	}

	@Test
	void xsdCreateWhenPatchReleaseThenNull() {
		File file = new File("spring-security-2.0.1.xsd");
		XsdFileMajorMinorVersion xsdFile = XsdFileMajorMinorVersion.create(file);
		assertThat(xsdFile).isNull();
	}

	@Test
	void xsdCreateWhenNotXsdFileThenNull() {
		File file = new File("spring-security-2.0.txt");
		XsdFileMajorMinorVersion xsdFile = XsdFileMajorMinorVersion.create(file);
		assertThat(xsdFile).isNull();
	}

	@Test
	void xsdCreateWhenNotStartWithSpringSecurityThenNull() {
		File file = new File("spring-securityNO-2.0.xsd");
		XsdFileMajorMinorVersion xsdFile = XsdFileMajorMinorVersion.create(file);
		assertThat(xsdFile).isNull();
	}

	@Test
	void isGreaterWhenMajorLarger() {
		MajorMinorVersion larger = new MajorMinorVersion(2,0);
		MajorMinorVersion smaller = new MajorMinorVersion(1,0);
		assertThat(larger.isGreaterThan(smaller)).isTrue();
		assertThat(smaller.isGreaterThan(larger)).isFalse();
	}

	@Test
	void isGreaterWhenMinorLarger() {
		MajorMinorVersion larger = new MajorMinorVersion(1,1);
		MajorMinorVersion smaller = new MajorMinorVersion(1,0);
		assertThat(larger.isGreaterThan(smaller)).isTrue();
		assertThat(smaller.isGreaterThan(larger)).isFalse();
	}

	@Test
	void isGreaterWhenMajorAndMinorLarger() {
		MajorMinorVersion larger = new MajorMinorVersion(2,1);
		MajorMinorVersion smaller = new MajorMinorVersion(1,0);
		assertThat(larger.isGreaterThan(smaller)).isTrue();
		assertThat(smaller.isGreaterThan(larger)).isFalse();
	}

	@Test
	void isGreaterWhenSame() {
		MajorMinorVersion first = new MajorMinorVersion(1,0);
		MajorMinorVersion second = new MajorMinorVersion(1,0);
		assertThat(first.isGreaterThan(second)).isFalse();
		assertThat(second.isGreaterThan(first)).isFalse();
	}
}
