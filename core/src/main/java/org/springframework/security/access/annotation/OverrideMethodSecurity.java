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

package org.springframework.security.access.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation combined with secure annotations such as <code>@Secured</code> for
 * overriding method's declaring class level security attributes.
 *
 * For example:
 *
 * <pre>
 * public class CrudRepository&lt;T&gt; {
 *
 *   public void create(T entity) {
 *
 *   }
 *   public void update(T entity) {
 *
 *   }
 *   public void delete(T entity) {
 *
 *   }
 *
 * }
 *
 * &#064;Secured({ &quot;ROLE_USER&quot; })
 * &#064;OverrideMethodSecurity
 * public class ContractRepository extends CrudRepository&lt;Contract&gt; {
 *
 * }
 * </pre> Otherwise you need redeclare methods without this annotation: <pre>
 * &#064;Secured({ &quot;ROLE_USER&quot; })
 * public class ContractRepository extends CrudRepository&lt;Contract&gt; {
 *
 *   &#064;Override
 *   public void create(Contract contract) {
 *     super.create(contract);
 *   }
 *
 *   &#064;Override
 *   public void update(Contract contract) {
 *     super.update(contract);
 *   }
 *
 *   &#064;Override
 *   public void delete(Contract contract) {
 *     super.delete(contract);
 *   }
 *
 * }
 * </pre>
 *
 * @author Yanming Zhou
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface OverrideMethodSecurity {

}
