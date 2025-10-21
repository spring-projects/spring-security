/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.access.intercept.aspectj;

/**
 * Called by the {@link AspectJMethodSecurityInterceptor} when it wishes for the AspectJ
 * processing to continue. Typically implemented in the <code>around()</code> advice as a
 * simple <code>return proceed();</code> statement.
 *
 * @author Ben Alex
 * @deprecated This class will be removed from the public API. Please either use
 * `spring-security-aspects`, Spring Security's method security support or create your own
 * class that uses Spring AOP annotations.
 */
@Deprecated
public interface AspectJCallback {

	Object proceedWithObject();

}
