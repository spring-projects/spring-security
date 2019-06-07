/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.messaging.access.expression;

import org.springframework.expression.EvaluationContext;

/**
 *
/**
 * Allows post processing the {@link EvaluationContext}
 *
 * <p>
 * This API is intentionally kept package scope as it may evolve over time.
 * </p>
 *
 * @author Daniel Bustamante Ospina
 * @since 5.2
 */
interface EvaluationContextPostProcessor<I> {

	/**
	 * Allows post processing of the {@link EvaluationContext}. Implementations
	 * may return a new instance of {@link EvaluationContext} or modify the
	 * {@link EvaluationContext} that was passed in.
	 *
	 * @param context
	 *            the original {@link EvaluationContext}
	 * @param invocation
	 *            the security invocation object (i.e. Message)
	 * @return the upated context.
	 */
	EvaluationContext postProcess(EvaluationContext context, I invocation);
}
