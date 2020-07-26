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

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.springframework.util.Assert;

/**
 * Handler for analyzing {@link Throwable} instances.
 *
 * Can be subclassed to customize its behavior.
 *
 * @author Andreas Senft
 * @since 2.0
 */
public class ThrowableAnalyzer {

	/**
	 * Default extractor for {@link Throwable} instances.
	 *
	 * @see Throwable#getCause()
	 */
	public static final ThrowableCauseExtractor DEFAULT_EXTRACTOR = throwable -> throwable.getCause();

	/**
	 * Default extractor for {@link InvocationTargetException} instances.
	 *
	 * @see InvocationTargetException#getTargetException()
	 */
	public static final ThrowableCauseExtractor INVOCATIONTARGET_EXTRACTOR = throwable -> {
		verifyThrowableHierarchy(throwable, InvocationTargetException.class);
		return ((InvocationTargetException) throwable).getTargetException();
	};

	/**
	 * Comparator to order classes ascending according to their hierarchy relation. If two
	 * classes have a hierarchical relation, the "higher" class is considered to be
	 * greater by this comparator.<br>
	 * For hierarchically unrelated classes their fully qualified name will be compared.
	 */
	private static final Comparator<Class<? extends Throwable>> CLASS_HIERARCHY_COMPARATOR = (class1, class2) -> {
		if (class1.isAssignableFrom(class2)) {
			return 1;
		}
		else if (class2.isAssignableFrom(class1)) {
			return -1;
		}
		else {
			return class1.getName().compareTo(class2.getName());
		}
	};

	/**
	 * Map of registered cause extractors. key: Class&lt;Throwable&gt;; value:
	 * ThrowableCauseExctractor
	 */
	private final Map<Class<? extends Throwable>, ThrowableCauseExtractor> extractorMap;

	/**
	 * Creates a new <code>ThrowableAnalyzer</code> instance.
	 */
	public ThrowableAnalyzer() {
		this.extractorMap = new TreeMap<>(CLASS_HIERARCHY_COMPARATOR);

		initExtractorMap();
	}

	/**
	 * Registers a <code>ThrowableCauseExtractor</code> for the specified type. <i>Can be
	 * used in subclasses overriding {@link #initExtractorMap()}.</i>
	 * @param throwableType the type (has to be a subclass of <code>Throwable</code>)
	 * @param extractor the associated <code>ThrowableCauseExtractor</code> (not
	 * <code>null</code>)
	 * @throws IllegalArgumentException if one of the arguments is invalid
	 */
	protected final void registerExtractor(Class<? extends Throwable> throwableType,
			ThrowableCauseExtractor extractor) {
		Assert.notNull(extractor, "Invalid extractor: null");

		this.extractorMap.put(throwableType, extractor);
	}

	/**
	 * Initializes associations between <code>Throwable</code>s and
	 * <code>ThrowableCauseExtractor</code>s. The default implementation performs the
	 * following registrations:
	 * <ul>
	 * <li>{@link #DEFAULT_EXTRACTOR} for {@link Throwable}</li>
	 * <li>{@link #INVOCATIONTARGET_EXTRACTOR} for {@link InvocationTargetException}</li>
	 * </ul>
	 * <br>
	 * Subclasses overriding this method are encouraged to invoke the super method to
	 * perform the default registrations. They can register additional extractors as
	 * required.
	 * <p>
	 * Note: An extractor registered for a specific type is applicable for that type
	 * <i>and all subtypes thereof</i>. However, extractors registered to more specific
	 * types are guaranteed to be resolved first. So in the default case
	 * InvocationTargetExceptions will be handled by {@link #INVOCATIONTARGET_EXTRACTOR}
	 * while all other throwables are handled by {@link #DEFAULT_EXTRACTOR}.
	 *
	 * @see #registerExtractor(Class, ThrowableCauseExtractor)
	 */
	protected void initExtractorMap() {
		registerExtractor(InvocationTargetException.class, INVOCATIONTARGET_EXTRACTOR);
		registerExtractor(Throwable.class, DEFAULT_EXTRACTOR);
	}

	/**
	 * Returns an array containing the classes for which extractors are registered. The
	 * order of the classes is the order in which comparisons will occur for resolving a
	 * matching extractor.
	 * @return the types for which extractors are registered
	 */
	@SuppressWarnings("unchecked")
	final Class<? extends Throwable>[] getRegisteredTypes() {
		Set<Class<? extends Throwable>> typeList = this.extractorMap.keySet();
		return typeList.toArray(new Class[0]);
	}

	/**
	 * Determines the cause chain of the provided <code>Throwable</code>. The returned
	 * array contains all throwables extracted from the stacktrace, using the registered
	 * {@link ThrowableCauseExtractor extractors}. The elements of the array are ordered:
	 * The first element is the passed in throwable itself. The following elements appear
	 * in their order downward the stacktrace.
	 * <p>
	 * Note: If no {@link ThrowableCauseExtractor} is registered for this instance then
	 * the returned array will always only contain the passed in throwable.
	 * @param throwable the <code>Throwable</code> to analyze
	 * @return an array of all determined throwables from the stacktrace
	 * @throws IllegalArgumentException if the throwable is <code>null</code>
	 *
	 * @see #initExtractorMap()
	 */
	public final Throwable[] determineCauseChain(Throwable throwable) {
		if (throwable == null) {
			throw new IllegalArgumentException("Invalid throwable: null");
		}

		List<Throwable> chain = new ArrayList<>();
		Throwable currentThrowable = throwable;

		while (currentThrowable != null) {
			chain.add(currentThrowable);
			currentThrowable = extractCause(currentThrowable);
		}

		return chain.toArray(new Throwable[0]);
	}

	/**
	 * Extracts the cause of the given throwable using an appropriate extractor.
	 * @param throwable the <code>Throwable</code> (not <code>null</code>
	 * @return the cause, may be <code>null</code> if none could be resolved
	 */
	private Throwable extractCause(Throwable throwable) {
		for (Map.Entry<Class<? extends Throwable>, ThrowableCauseExtractor> entry : this.extractorMap.entrySet()) {
			Class<? extends Throwable> throwableType = entry.getKey();
			if (throwableType.isInstance(throwable)) {
				ThrowableCauseExtractor extractor = entry.getValue();
				return extractor.extractCause(throwable);
			}
		}

		return null;
	}

	/**
	 * Returns the first throwable from the passed in array that is assignable to the
	 * provided type. A returned instance is safe to be cast to the specified type.
	 * <p>
	 * If the passed in array is null or empty this method returns <code>null</code>.
	 * @param throwableType the type to look for
	 * @param chain the array (will be processed in element order)
	 * @return the found <code>Throwable</code>, <code>null</code> if not found
	 * @throws IllegalArgumentException if the provided type is <code>null</code> or no
	 * subclass of <code>Throwable</code>
	 */
	public final Throwable getFirstThrowableOfType(Class<? extends Throwable> throwableType, Throwable[] chain) {
		if (chain != null) {
			for (Throwable t : chain) {
				if ((t != null) && throwableType.isInstance(t)) {
					return t;
				}
			}
		}

		return null;
	}

	/**
	 * Verifies that the provided throwable is a valid subclass of the provided type (or
	 * of the type itself). If <code>expectdBaseType</code> is <code>null</code>, no check
	 * will be performed.
	 * <p>
	 * Can be used for verification purposes in implementations of
	 * {@link ThrowableCauseExtractor extractors}.
	 * @param throwable the <code>Throwable</code> to check
	 * @param expectedBaseType the type to check against
	 * @throws IllegalArgumentException if <code>throwable</code> is either
	 * <code>null</code> or its type is not assignable to <code>expectedBaseType</code>
	 */
	public static void verifyThrowableHierarchy(Throwable throwable, Class<? extends Throwable> expectedBaseType) {
		if (expectedBaseType == null) {
			return;
		}

		if (throwable == null) {
			throw new IllegalArgumentException("Invalid throwable: null");
		}
		Class<? extends Throwable> throwableType = throwable.getClass();

		if (!expectedBaseType.isAssignableFrom(throwableType)) {
			throw new IllegalArgumentException("Invalid type: '" + throwableType.getName()
					+ "'. Has to be a subclass of '" + expectedBaseType.getName() + "'");
		}
	}

}
