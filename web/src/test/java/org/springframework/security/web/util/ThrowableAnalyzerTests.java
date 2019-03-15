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
package org.springframework.security.web.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.lang.reflect.InvocationTargetException;

import org.junit.Before;
import org.junit.Test;

/**
 * Test cases for {@link ThrowableAnalyzer}.
 *
 * @author Andreas Senft
 */
@SuppressWarnings("unchecked")
public class ThrowableAnalyzerTests {

	/**
	 * Exception for testing purposes. The cause is not retrievable by {@link #getCause()}
	 * .
	 */
	public static final class NonStandardException extends Exception {

		private Throwable cause;

		public NonStandardException(String message, Throwable cause) {
			super(message);
			this.cause = cause;
		}

		public Throwable resolveCause() {
			return this.cause;
		}
	}

	/**
	 * <code>ThrowableCauseExtractor</code> for handling <code>NonStandardException</code>
	 * instances.
	 */
	public static final class NonStandardExceptionCauseExtractor
			implements ThrowableCauseExtractor {

		public Throwable extractCause(Throwable throwable) {
			ThrowableAnalyzer.verifyThrowableHierarchy(throwable,
					NonStandardException.class);
			return ((NonStandardException) throwable).resolveCause();
		}

	}

	/**
	 * An array of nested throwables for testing. The cause of element 0 is element 1, the
	 * cause of element 1 is element 2 and so on.
	 */
	private Throwable[] testTrace;

	/**
	 * Plain <code>ThrowableAnalyzer</code>.
	 */
	private ThrowableAnalyzer standardAnalyzer;

	/**
	 * Enhanced <code>ThrowableAnalyzer</code> capable to process
	 * <code>NonStandardException</code>s.
	 */
	private ThrowableAnalyzer nonstandardAnalyzer;

	@Before
	public void setUp() throws Exception {

		// Set up test trace
		this.testTrace = new Throwable[7];
		this.testTrace[6] = new IllegalArgumentException("Test_6");
		this.testTrace[5] = new Throwable("Test_5", this.testTrace[6]);
		this.testTrace[4] = new InvocationTargetException(this.testTrace[5], "Test_4");
		this.testTrace[3] = new Exception("Test_3", this.testTrace[4]);
		this.testTrace[2] = new NonStandardException("Test_2", this.testTrace[3]);
		this.testTrace[1] = new RuntimeException("Test_1", this.testTrace[2]);
		this.testTrace[0] = new Exception("Test_0", this.testTrace[1]);

		// Set up standard analyzer
		this.standardAnalyzer = new ThrowableAnalyzer();

		// Set up nonstandard analyzer
		this.nonstandardAnalyzer = new ThrowableAnalyzer() {

			/**
			 * @see org.springframework.security.web.util.ThrowableAnalyzer#initExtractorMap()
			 */
			@Override
			protected void initExtractorMap() {
				super.initExtractorMap();
				// register extractor for NonStandardException
				registerExtractor(NonStandardException.class,
						new NonStandardExceptionCauseExtractor());
			}
		};
	}

	@Test
	public void testRegisterExtractorWithInvalidExtractor() {
		try {
			new ThrowableAnalyzer() {

				/**
				 * @see org.springframework.security.web.util.ThrowableAnalyzer#initExtractorMap()
				 */
				@Override
				protected void initExtractorMap() {
					// null is no valid extractor
					super.registerExtractor(Exception.class, null);
				}
			};

			fail("IllegalArgumentExpected");
		}
		catch (IllegalArgumentException e) {
			// ok
		}
	}

	@Test
	public void testGetRegisteredTypes() {

		Class[] registeredTypes = this.nonstandardAnalyzer.getRegisteredTypes();

		for (int i = 0; i < registeredTypes.length; ++i) {
			Class clazz = registeredTypes[i];

			// The most specific types have to occur first.
			for (int j = 0; j < i; ++j) {
				Class prevClazz = registeredTypes[j];

				assertThat(prevClazz.isAssignableFrom(clazz)).withFailMessage(
						"Unexpected order of registered classes: " + prevClazz
								+ " is assignable from " + clazz).isFalse();
			}
		}
	}

	@Test
	public void testDetermineCauseChainWithNoExtractors() {
		ThrowableAnalyzer analyzer = new ThrowableAnalyzer() {

			/**
			 * @see org.springframework.security.web.util.ThrowableAnalyzer#initExtractorMap()
			 */
			@Override
			protected void initExtractorMap() {
				// skip default initialization
			}
		};

		assertThat(analyzer.getRegisteredTypes().length).withFailMessage(
				"Unexpected number of registered types").isEqualTo(0);

		Throwable t = this.testTrace[0];
		Throwable[] chain = analyzer.determineCauseChain(t);
		// Without extractors only the root throwable is available
		assertThat(chain.length).as("Unexpected chain size").isEqualTo(1);
		assertThat(chain[0]).as("Unexpected chain entry").isEqualTo(t);
	}

	@Test
	public void testDetermineCauseChainWithDefaultExtractors() {
		ThrowableAnalyzer analyzer = this.standardAnalyzer;

		assertThat(analyzer.getRegisteredTypes().length).withFailMessage(
				"Unexpected number of registered types").isEqualTo(2);

		Throwable[] chain = analyzer.determineCauseChain(this.testTrace[0]);

		// Element at index 2 is a NonStandardException which cannot be analyzed further
		// by default
		assertThat(chain.length).as("Unexpected chain size").isEqualTo(3);
		for (int i = 0; i < 3; ++i) {
			assertThat(chain[i]).withFailMessage(
					"Unexpected chain entry: " + i).isEqualTo(this.testTrace[i]);
		}
	}

	@Test
	public void testDetermineCauseChainWithCustomExtractors() {
		ThrowableAnalyzer analyzer = this.nonstandardAnalyzer;

		Throwable[] chain = analyzer.determineCauseChain(this.testTrace[0]);

		assertThat(chain.length).as("Unexpected chain size").isEqualTo(
				this.testTrace.length);
		for (int i = 0; i < chain.length; ++i) {
			assertThat(chain[i]).withFailMessage(
					"Unexpected chain entry: " + i).isEqualTo(this.testTrace[i]);
		}
	}

	@Test
	public void testGetFirstThrowableOfTypeWithSuccess1() {
		ThrowableAnalyzer analyzer = this.nonstandardAnalyzer;

		Throwable[] chain = analyzer.determineCauseChain(this.testTrace[0]);

		Throwable result = analyzer.getFirstThrowableOfType(Exception.class, chain);

		assertThat(result).as("null not expected").isNotNull();
		assertThat(result).as("Unexpected throwable found").isEqualTo(this.testTrace[0]);
	}

	@Test
	public void testGetFirstThrowableOfTypeWithSuccess2() {
		ThrowableAnalyzer analyzer = this.nonstandardAnalyzer;

		Throwable[] chain = analyzer.determineCauseChain(this.testTrace[0]);

		Throwable result = analyzer.getFirstThrowableOfType(NonStandardException.class,
				chain);

		assertThat(result).as("null not expected").isNotNull();
		assertThat(result).as("Unexpected throwable found").isEqualTo(this.testTrace[2]);
	}

	@Test
	public void testGetFirstThrowableOfTypeWithFailure() {
		ThrowableAnalyzer analyzer = this.nonstandardAnalyzer;

		Throwable[] chain = analyzer.determineCauseChain(this.testTrace[0]);

		// IllegalStateException not in trace
		Throwable result = analyzer.getFirstThrowableOfType(IllegalStateException.class,
				chain);

		assertThat(result).as("null expected").isNull();
	}

	@Test
	public void testVerifyThrowableHierarchyWithExactType() {

		Throwable throwable = new IllegalStateException("Test");
		ThrowableAnalyzer.verifyThrowableHierarchy(throwable,
				IllegalStateException.class);
		// No exception expected
	}

	@Test
	public void testVerifyThrowableHierarchyWithCompatibleType() {

		Throwable throwable = new IllegalStateException("Test");
		ThrowableAnalyzer.verifyThrowableHierarchy(throwable, Exception.class);
		// No exception expected
	}

	@Test
	public void testVerifyThrowableHierarchyWithNull() {
		try {
			ThrowableAnalyzer.verifyThrowableHierarchy(null, Throwable.class);
			fail("IllegalArgumentException expected");
		}
		catch (IllegalArgumentException e) {
			// ok
		}
	}

	@Test
	public void testVerifyThrowableHierarchyWithNonmatchingType() {

		Throwable throwable = new IllegalStateException("Test");
		try {
			ThrowableAnalyzer.verifyThrowableHierarchy(throwable,
					InvocationTargetException.class);
			fail("IllegalArgumentException expected");
		}
		catch (IllegalArgumentException e) {
			// ok
		}
	}
}
