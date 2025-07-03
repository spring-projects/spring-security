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

package org.springframework.security;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

import org.apache.commons.lang3.ObjectUtils;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AssignableTypeFilter;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.ReflectionUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests that Spring Security classes that implements {@link Serializable} and have the
 * same serial version as {@link SpringSecurityCoreVersion#SERIAL_VERSION_UID} can be
 * deserialized from a previous minor version.
 * <p>
 * For example, all classes from version 6.2.x that matches the previous requirement
 * should be serialized and saved to a folder, and then later on, in 6.3.x, it is verified
 * if they can be deserialized
 *
 * @author Marcus da Coregio
 * @since 6.2.2
 * @see <a href="https://github.com/spring-projects/spring-security/issues/3737">GitHub
 * Issue #3737</a>
 */
class SpringSecurityCoreVersionSerializableTests {

	static final long securitySerialVersionUid = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	static Path currentVersionFolder = Paths.get("src/test/resources/serialized/" + getCurrentVersion());

	static Path previousVersionFolder = Paths.get("src/test/resources/serialized/" + getPreviousVersion());

	@ParameterizedTest
	@MethodSource("getClassesToSerialize")
	void serializeAndDeserializeAreEqual(Class<?> clazz) throws Exception {
		Object expected = SerializationSamples.instancioWithDefaults(clazz).create();
		assertThat(expected).isInstanceOf(clazz);
		try (ByteArrayOutputStream out = new ByteArrayOutputStream();
				ObjectOutputStream objectOutputStream = new ObjectOutputStream(out)) {
			objectOutputStream.writeObject(expected);
			objectOutputStream.flush();

			try (ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
					ObjectInputStream objectInputStream = new ObjectInputStream(in)) {
				Object deserialized = objectInputStream.readObject();
				// Ignore transient fields Event classes extend from EventObject which has
				// transient source property
				Set<String> transientFieldNames = new HashSet();
				Set<Class<?>> visitedClasses = new HashSet();
				collectTransientFieldNames(transientFieldNames, visitedClasses, clazz);
				assertThat(deserialized).usingRecursiveComparison()
					.ignoringFields(transientFieldNames.toArray(new String[0]))
					// RuntimeExceptions do not fully work but ensure the message does
					.withComparatorForType((lhs, rhs) -> ObjectUtils.compare(lhs.getMessage(), rhs.getMessage()),
							RuntimeException.class)
					.isEqualTo(expected);
			}
		}
	}

	private static void collectTransientFieldNames(Set<String> transientFieldNames, Set<Class<?>> visitedClasses,
			Class<?> clazz) {
		if (!visitedClasses.add(clazz) || clazz.isPrimitive()) {
			return;
		}
		ReflectionUtils.doWithFields(clazz, (field) -> {
			if (Modifier.isTransient(field.getModifiers())) {
				transientFieldNames.add(field.getName());
			}
			collectTransientFieldNames(transientFieldNames, visitedClasses, field.getType());
		});
	}

	@ParameterizedTest
	@MethodSource("getClassesToSerialize")
	@Disabled("This method should only be used to serialize the classes once")
	void serializeCurrentVersionClasses(Class<?> clazz) throws Exception {
		Files.createDirectories(currentVersionFolder);
		Path filePath = Paths.get(currentVersionFolder.toAbsolutePath() + "/" + clazz.getName() + ".serialized");
		File file = filePath.toFile();
		if (file.exists()) {
			return;
		}
		Files.createFile(filePath);
		try (FileOutputStream fileOutputStream = new FileOutputStream(file);
				ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream)) {
			Object instance = SerializationSamples.instancioWithDefaults(clazz).create();
			assertThat(instance).isInstanceOf(clazz);
			objectOutputStream.writeObject(instance);
			objectOutputStream.flush();
		}
		catch (NotSerializableException ex) {
			Files.delete(filePath);
			fail("Could not serialize " + clazz.getName(), ex);
		}
	}

	@ParameterizedTest
	@MethodSource("getCurrentSerializedFiles")
	void shouldBeAbleToDeserializeClassFromCurrentVersion(Path filePath) {
		try (FileInputStream fileInputStream = new FileInputStream(filePath.toFile());
				ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {
			Object obj = objectInputStream.readObject();
			Class<?> clazz = Class.forName(filePath.getFileName().toString().replace(".serialized", ""));
			assertThat(obj).isInstanceOf(clazz);
		}
		catch (IOException | ClassNotFoundException ex) {
			fail("Could not deserialize " + filePath, ex);
		}
	}

	static Stream<Path> getCurrentSerializedFiles() throws Exception {
		assertThat(currentVersionFolder.toFile().exists())
			.as("Make sure that the " + currentVersionFolder + " exists and is not empty")
			.isTrue();
		return getClassesToSerialize().map((clazz) -> currentVersionFolder.resolve(clazz.getName() + ".serialized"));
	}

	@ParameterizedTest
	@MethodSource("getPreviousSerializedFiles")
	void shouldBeAbleToDeserializeClassFromPreviousVersion(Path filePath) {
		try (FileInputStream fileInputStream = new FileInputStream(filePath.toFile());
				ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {
			Object obj = objectInputStream.readObject();
			Class<?> clazz = Class.forName(filePath.getFileName().toString().replace(".serialized", ""));
			assertThat(obj).isInstanceOf(clazz);
		}
		catch (IOException | ClassNotFoundException ex) {
			fail("Could not deserialize " + filePath, ex);
		}
	}

	static Stream<Path> getPreviousSerializedFiles() throws IOException {
		assertThat(previousVersionFolder.toFile().exists())
			.as("Make sure that the " + previousVersionFolder + " exists and is not empty")
			.isTrue();
		try (Stream<Path> files = Files.list(previousVersionFolder)) {
			if (files.findFirst().isEmpty()) {
				fail("Please make sure to run SpringSecurityCoreVersionSerializableTests#serializeCurrentVersionClasses for the "
						+ getPreviousVersion() + " version");
			}
		}
		return Files.list(previousVersionFolder);
	}

	@Test
	void allSerializableClassesShouldHaveSerialVersionOrSuppressWarnings() throws Exception {
		ClassPathScanningCandidateComponentProvider provider = new ClassPathScanningCandidateComponentProvider(false);
		provider.addIncludeFilter(new AssignableTypeFilter(Serializable.class));
		List<Class<?>> classes = new ArrayList<>();

		Set<BeanDefinition> components = provider.findCandidateComponents("org/springframework/security");
		for (BeanDefinition component : components) {
			Class<?> clazz = Class.forName(component.getBeanClassName());
			if (clazz.isEnum()) {
				continue;
			}
			if (clazz.getName().contains("Tests")) {
				continue;
			}
			boolean hasSerialVersion = Stream.of(clazz.getDeclaredFields())
				.map(Field::getName)
				.anyMatch((n) -> n.equals("serialVersionUID"));
			SuppressWarnings suppressWarnings = clazz.getAnnotation(SuppressWarnings.class);
			boolean hasSerialIgnore = suppressWarnings == null
					|| Arrays.asList(suppressWarnings.value()).contains("Serial");
			if (!hasSerialVersion && !hasSerialIgnore) {
				classes.add(clazz);
				continue;
			}
			boolean isReachable = Modifier.isPublic(clazz.getModifiers());
			boolean hasSampleSerialization = currentVersionFolder.resolve(clazz.getName() + ".serialized")
				.toFile()
				.exists();
			if (hasSerialVersion && isReachable && !hasSampleSerialization) {
				classes.add(clazz);
			}
		}
		assertThat(classes).describedAs(
				"Found Serializable classes that are either missing a serialVersionUID or a @SuppressWarnings or a sample serialized file")
			.isEmpty();
	}

	static Stream<Class<?>> getClassesToSerialize() throws Exception {
		ClassPathScanningCandidateComponentProvider provider = new ClassPathScanningCandidateComponentProvider(false);
		provider.addIncludeFilter(new AssignableTypeFilter(Serializable.class));
		List<Class<?>> classes = new ArrayList<>();

		Set<BeanDefinition> components = provider.findCandidateComponents("org/springframework/security");
		for (BeanDefinition component : components) {
			Class<?> clazz = Class.forName(component.getBeanClassName());
			boolean isAbstract = Modifier.isAbstract(clazz.getModifiers());
			if (isAbstract) {
				continue;
			}
			boolean matchesExpectedSerialVersion = ObjectStreamClass.lookup(clazz)
				.getSerialVersionUID() == securitySerialVersionUid;
			boolean isUnderTest = SerializationSamples.generatorByClassName.containsKey(clazz);
			if (matchesExpectedSerialVersion || isUnderTest) {
				classes.add(clazz);
			}
		}
		return classes.stream();
	}

	private static String getCurrentVersion() {
		String version = System.getProperty("springSecurityVersion");
		String[] parts = version.split("\\.");
		parts[2] = "x";
		return String.join(".", parts);
	}

	private static String getPreviousVersion() {
		String version = System.getProperty("springSecurityVersion");
		String[] parts = version.split("\\.");
		parts[1] = String.valueOf(Integer.parseInt(parts[1]) - 1);
		// FIXME: the 7 should not be hardcoded
		if ("7".equals(parts[0]) && "-1".equals(parts[1])) {
			// if it is version 7.0.x, the previous version is 6.5.x
			parts[0] = String.valueOf(Integer.parseInt(parts[0]) - 1);
			parts[1] = "5"; // FIXME: this should not be hard coded
		}
		parts[2] = "x";
		return String.join(".", parts);
	}

}
