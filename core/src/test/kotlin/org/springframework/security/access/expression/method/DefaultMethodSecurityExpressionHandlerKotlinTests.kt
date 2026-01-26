/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.access.expression.method

import io.mockk.every
import io.mockk.mockk
import org.aopalliance.intercept.MethodInvocation
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.expression.EvaluationContext
import org.springframework.expression.Expression
import org.springframework.security.core.Authentication
import java.util.stream.Stream
import kotlin.reflect.jvm.internal.impl.load.kotlin.JvmType
import kotlin.reflect.jvm.javaMethod

/**
 * @author Blagoja Stamatovski
 */
class DefaultMethodSecurityExpressionHandlerKotlinTests {
    private object Foo {
        fun bar() {
        }
    }

    private lateinit var authentication: Authentication
    private lateinit var methodInvocation: MethodInvocation

    private val handler: MethodSecurityExpressionHandler = DefaultMethodSecurityExpressionHandler()

    @BeforeEach
    fun setUp()  {
        authentication = mockk()
        methodInvocation = mockk()

        every { methodInvocation.`this` } returns { Foo }
        every { methodInvocation.method } answers { Foo::bar.javaMethod!! }
        every { methodInvocation.arguments } answers { arrayOf<JvmType.Object>() }
    }

    @Test
    fun `filters non-empty maps`() {
        val expression: Expression = handler.expressionParser.parseExpression("filterObject.key eq 'key2'")
        val context: EvaluationContext = handler.createEvaluationContext(
            /* authentication = */ authentication,
            /* invocation = */ methodInvocation,
        )
        val nonEmptyMap: Map<String, String> = mapOf(
            "key1" to "value1",
            "key2" to "value2",
            "key3" to "value3",
        )

        val filtered: Any = handler.filter(
            /* filterTarget = */ nonEmptyMap,
            /* filterExpression = */ expression,
            /* ctx = */ context,
        )

        assertThat(filtered).isInstanceOf(Map::class.java)
        @Suppress("UNCHECKED_CAST")
        val result = filtered as Map<String, String>
        assertThat(result).hasSize(1)
        assertThat(result).containsKey("key2")
        assertThat(result).containsValue("value2")
    }

    @Test
    fun `filters empty maps`() {
        val expression: Expression = handler.expressionParser.parseExpression("filterObject.key eq 'key2'")
        val context: EvaluationContext = handler.createEvaluationContext(
            /* authentication = */ authentication,
            /* invocation = */ methodInvocation,
        )
        val emptyMap: Map<String, String> = emptyMap()

        val filtered: Any = handler.filter(
            /* filterTarget = */ emptyMap,
            /* filterExpression = */ expression,
            /* ctx = */ context,
        )

        assertThat(filtered).isInstanceOf(Map::class.java)
        @Suppress("UNCHECKED_CAST")
        val result = filtered as Map<String, String>
        assertThat(result).hasSize(0)
    }

    @Test
    fun `filters non-empty collections`() {
        val expression: Expression = handler.expressionParser.parseExpression("filterObject eq 'string2'")
        val context: EvaluationContext = handler.createEvaluationContext(
            /* authentication = */ authentication,
            /* invocation = */ methodInvocation,
        )
        val nonEmptyCollection: Collection<String> = listOf(
            "string1",
            "string2",
            "string1",
        )

        val filtered: Any = handler.filter(
            /* filterTarget = */ nonEmptyCollection,
            /* filterExpression = */ expression,
            /* ctx = */ context,
        )

        assertThat(filtered).isInstanceOf(Collection::class.java)
        @Suppress("UNCHECKED_CAST")
        val result = filtered as Collection<String>
        assertThat(result).hasSize(1)
        assertThat(result).contains("string2")
    }

    @Test
    fun `filters empty collections`() {
        val expression: Expression = handler.expressionParser.parseExpression("filterObject eq 'string2'")
        val context: EvaluationContext = handler.createEvaluationContext(
            /* authentication = */ authentication,
            /* invocation = */ methodInvocation,
        )
        val emptyCollection: Collection<String> = emptyList()

        val filtered: Any = handler.filter(
            /* filterTarget = */ emptyCollection,
            /* filterExpression = */ expression,
            /* ctx = */ context,
        )

        assertThat(filtered).isInstanceOf(Collection::class.java)
        @Suppress("UNCHECKED_CAST")
        val result = filtered as Collection<String>
        assertThat(result).hasSize(0)
    }

    @Test
    fun `filters non-empty arrays`() {
        val expression: Expression = handler.expressionParser.parseExpression("filterObject eq 'string2'")
        val context: EvaluationContext = handler.createEvaluationContext(
            /* authentication = */ authentication,
            /* invocation = */ methodInvocation,
        )
        val nonEmptyArray: Array<String> = arrayOf(
            "string1",
            "string2",
            "string1",
        )

        val filtered: Any = handler.filter(
            /* filterTarget = */ nonEmptyArray,
            /* filterExpression = */ expression,
            /* ctx = */ context,
        )

        assertThat(filtered).isInstanceOf(Array<String>::class.java)
        @Suppress("UNCHECKED_CAST")
        val result = filtered as Array<String>
        assertThat(result).hasSize(1)
        assertThat(result).contains("string2")
    }

    @Test
    fun `filters empty arrays`() {
        val expression: Expression = handler.expressionParser.parseExpression("filterObject eq 'string2'")
        val context: EvaluationContext = handler.createEvaluationContext(
            /* authentication = */ authentication,
            /* invocation = */ methodInvocation,
        )
        val emptyArray: Array<String> = emptyArray()

        val filtered: Any = handler.filter(
            /* filterTarget = */ emptyArray,
            /* filterExpression = */ expression,
            /* ctx = */ context,
        )

        assertThat(filtered).isInstanceOf(Array<String>::class.java)
        @Suppress("UNCHECKED_CAST")
        val result = filtered as Array<String>
        assertThat(result).hasSize(0)
    }

    @Test
    fun `filters non-empty streams`() {
        val expression: Expression = handler.expressionParser.parseExpression("filterObject eq 'string2'")
        val context: EvaluationContext = handler.createEvaluationContext(
            /* authentication = */ authentication,
            /* invocation = */ methodInvocation,
        )
        val nonEmptyStream: Stream<String> = listOf(
            "string1",
            "string2",
            "string1",
        ).stream()

        val filtered: Any = handler.filter(
            /* filterTarget = */ nonEmptyStream,
            /* filterExpression = */ expression,
            /* ctx = */ context,
        )

        assertThat(filtered).isInstanceOf(Stream::class.java)
        @Suppress("UNCHECKED_CAST")
        val result = (filtered as Stream<String>).toList()
        assertThat(result).hasSize(1)
        assertThat(result).contains("string2")
    }

    @Test
    fun `filters empty streams`() {
        val expression: Expression = handler.expressionParser.parseExpression("filterObject eq 'string2'")
        val context: EvaluationContext = handler.createEvaluationContext(
            /* authentication = */ authentication,
            /* invocation = */ methodInvocation,
        )
        val emptyStream: Stream<String> = emptyList<String>().stream()

        val filtered: Any = handler.filter(
            /* filterTarget = */ emptyStream,
            /* filterExpression = */ expression,
            /* ctx = */ context,
        )

        assertThat(filtered).isInstanceOf(Stream::class.java)
        @Suppress("UNCHECKED_CAST")
        val result = (filtered as Stream<String>).toList()
        assertThat(result).hasSize(0)
    }
}
