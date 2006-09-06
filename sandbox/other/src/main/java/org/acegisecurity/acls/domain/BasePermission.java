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
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision$
  */
public class BasePermission implements Permission {
    //~ Static fields/initializers =====================================================================================

    public static final Permission READ = new BasePermission(1 << 0, 'R'); // 1
    public static final Permission WRITE = new BasePermission(1 << 1, 'W'); // 2
    public static final Permission CREATE = new BasePermission(1 << 2, 'C'); // 4
    public static final Permission DELETE = new BasePermission(1 << 3, 'D'); // 8
    public static final Permission ADMINISTRATION = new BasePermission(1 << 4, 'A'); // 16

    //~ Instance fields ================================================================================================

    private char code;
    private int mask;

    //~ Constructors ===================================================================================================

    private BasePermission(int mask, char code) {
        this.mask = mask;
        this.code = code;
    }

    //~ Methods ========================================================================================================

    /**
     * Dynamically creates a <code>CumulativePermission</code> representing the active bits in the passed mask.
     * NB: Only uses <code>BasePermission</code>!
     *
     * @param mask to review
     *
     * @return DOCUMENT ME!
     */
    public static Permission buildFromMask(int mask) {
        CumulativePermission permission = new CumulativePermission();

        // TODO: Write the rest of it to iterate through the 32 bits and instantiate BasePermissions
        if (mask == 1) {
            permission.set(READ);
        }

        if (mask == 2) {
            permission.set(WRITE);
        }

        if (mask == 4) {
            permission.set(CREATE);
        }

        if (mask == 8) {
            permission.set(DELETE);
        }
        
        if (mask == 16) {
            permission.set(ADMINISTRATION);
        }

        return permission;
    }

    public boolean equals(Object arg0) {
        if (!(arg0 instanceof BasePermission)) {
            return false;
        }

        BasePermission rhs = (BasePermission) arg0;

        return (this.mask == rhs.getMask());
    }

    public int getMask() {
        return mask;
    }

    public String getPattern() {
        return AclFormattingUtils.printBinary(mask, code);
    }

    public String toString() {
        return "BasePermission[" + getPattern() + "=" + mask + "]";
    }
}
