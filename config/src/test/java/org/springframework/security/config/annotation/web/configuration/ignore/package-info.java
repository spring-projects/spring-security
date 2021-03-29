/*
 * Copyright 2002-2021 the original author or authors.
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

/**
 * Test package for path patterns that must be ignored by Spring Security and must be
 * indicated/notified through the output, it thanks to the
 * <code>DefaultSecurityFilterChain</code>'s constructor.
 *
 * <p>
 * <b>NOTE:</b> be advised that to test if a path(s) was really ignored or not, by
 * simplicity, is checking the output shown in the test report, it based with the pattern
 * <code>"Will not secure /ABC"</code>, where <code>ABC</code> was defined through the
 * <code>web.ignoring()</code> approach. Is very important edit the
 * <code>logback-test.xml</code> file (of this module) to change
 * <code>level="${sec.log.level:-WARN}"</code> to
 * <code>level="${sec.log.level:-INFO}"</code>
 *
 * <p>
 * In the handler methods do not return the view name (i.e:
 * <code>return "something"</code>) based on the path value (i.e:
 * <code>@GetMapping(path = "/something")</code>), otherwise the tests fail with:
 *
 * <pre class="code">
 * javax.servlet.ServletException:
 * Circular view path [something]:
 * would dispatch back to the current handler URL [/something] again.
 * Check your ViewResolver setup!
 * (Hint: This may be the result of an unspecified view, due to default view name generation.)
 * </pre>
 *
 * That's why the all handler methods are based with the
 * <code>return "something/something"</code> pattern.
 *
 * @author Manuel Jordan
 * @since 5.5
 */
package org.springframework.security.config.annotation.web.configuration.ignore;
