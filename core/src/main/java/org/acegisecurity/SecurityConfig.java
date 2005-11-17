/* Copyright 2004 Acegi Technology Pty Limited
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

package org.acegisecurity;

/**
 * Stores a {@link ConfigAttribute} as a <code>String</code>.
 *
 * @author <A HREF="mailto:ben.alex@fremerx.com">Ben Alex</A>
 * @version $Id$
 */
public class SecurityConfig implements ConfigAttribute {
    //~ Instance fields ========================================================

    private String attrib;

    //~ Constructors ===========================================================

    public SecurityConfig(String config) {
        this.attrib = config;
    }

    protected SecurityConfig() {
        throw new IllegalArgumentException("Cannot use default constructor");
    }

    //~ Methods ================================================================

    public String getAttribute() {
        return this.attrib;
    }

    public boolean equals(Object obj) {
        if (obj instanceof String) {
            return obj.equals(this.attrib);
        }

        if (obj instanceof ConfigAttribute) {
            ConfigAttribute attr = (ConfigAttribute) obj;

            return this.attrib.equals(attr.getAttribute());
        }

        return false;
    }

    public int hashCode() {
        return this.attrib.hashCode();
    }

    public String toString() {
        return this.attrib;
    }
}
