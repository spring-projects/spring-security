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
package org.acegisecurity.acls.domain;

import org.acegisecurity.acls.AclFormattingUtils;
import org.acegisecurity.acls.Permission;


/**
 * Represents a <code>Permission</code> that is constructed at runtime from other permissions.<p>Methods return
 * <code>this</code>, in order to facilitate method chaining.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CumulativePermission implements Permission {
    //~ Instance fields ================================================================================================

    private String pattern = THIRTY_TWO_RESERVED_OFF;
    private int mask = 0;

    //~ Methods ========================================================================================================

    public CumulativePermission clear(Permission permission) {
        this.mask &= ~permission.getMask();
        this.pattern = AclFormattingUtils.demergePatterns(this.pattern, permission.getPattern());

        return this;
    }

    public CumulativePermission clear() {
        this.mask = 0;
        this.pattern = THIRTY_TWO_RESERVED_OFF;

        return this;
    }

    public boolean equals(Object arg0) {
        if (!(arg0 instanceof CumulativePermission)) {
            return false;
        }

        CumulativePermission rhs = (CumulativePermission) arg0;

        return (this.mask == rhs.getMask());
    }
    
	public int hashCode() {
		return this.mask;
	}

	public int getMask() {
        return this.mask;
    }

    public String getPattern() {
        return this.pattern;
    }

    public CumulativePermission set(Permission permission) {
        this.mask |= permission.getMask();
        this.pattern = AclFormattingUtils.mergePatterns(this.pattern, permission.getPattern());

        return this;
    }

    public String toString() {
        return "CumulativePermission[" + pattern + "=" + this.mask + "]";
    }
}
