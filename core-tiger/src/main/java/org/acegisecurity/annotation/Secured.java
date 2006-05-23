/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Java 5 annotation for describing service layer security attributes.
 * 
 * <p>The <code>Secured</code> annotation is used to define a list of security 
 * configuration attributes for business methods.  This annotation can be used 
 * as a Java 5 alternative to XML configuration.
 * <p>For example:
 * <pre>
 *     &#64;Secured ({"ROLE_USER"})
 *     public void create(Contact contact);
 *     
 *     &#64;Secured ({"ROLE_USER", "ROLE_ADMIN"})
 *     public void update(Contact contact);
 *     
 *     &#64;Secured ({"ROLE_ADMIN"})
 *     public void delete(Contact contact);
 * </pre> 
 * @author Mark St.Godard
 * @version $Id$
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface Secured {
/**
     * Returns the list of security configuration attributes. 
     *   (i.e. ROLE_USER, ROLE_ADMIN etc.)
     * @return String[] The secure method attributes 
     */
    public String[] value();
}
