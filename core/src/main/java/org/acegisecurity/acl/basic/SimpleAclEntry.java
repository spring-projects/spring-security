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

package org.acegisecurity.acl.basic;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * Stores some privileges typical of a domain object.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SimpleAclEntry extends AbstractBasicAclEntry {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(SimpleAclEntry.class);

    // Base permissions we permit
    public static final int NOTHING = 0;
    public static final int ADMINISTRATION = (int) Math.pow(2, 0);
    public static final int READ = (int) Math.pow(2, 1);
    public static final int WRITE = (int) Math.pow(2, 2);
    public static final int CREATE = (int) Math.pow(2, 3);
    public static final int DELETE = (int) Math.pow(2, 4);

    // Combinations of base permissions we permit
    public static final int READ_WRITE_CREATE_DELETE = READ | WRITE | CREATE
        | DELETE;
    public static final int READ_WRITE_CREATE = READ | WRITE | CREATE;
    public static final int READ_WRITE = READ | WRITE;
    public static final int READ_WRITE_DELETE = READ | WRITE | DELETE;

    // Array required by the abstract superclass via getValidPermissions()
    private static final int[] validPermissions = {NOTHING, ADMINISTRATION, READ, WRITE, CREATE, DELETE, READ_WRITE_CREATE_DELETE, READ_WRITE_CREATE, READ_WRITE, READ_WRITE_DELETE};

    //~ Constructors ===========================================================

    /**
     * Allows {@link BasicAclDao} implementations to construct this object
     * using <code>newInstance()</code>.
     * 
     * <P>
     * Normal classes should <B>not</B> use this default constructor.
     * </p>
     */
    public SimpleAclEntry() {
        super();
    }

    public SimpleAclEntry(Object recipient,
        AclObjectIdentity aclObjectIdentity,
        AclObjectIdentity aclObjectParentIdentity, int mask) {
        super(recipient, aclObjectIdentity, aclObjectParentIdentity, mask);
    }

    //~ Methods ================================================================

    public int[] getValidPermissions() {
        return validPermissions;
    }

    public String printPermissionsBlock(int i) {
        StringBuffer sb = new StringBuffer();

        if (isPermitted(i, ADMINISTRATION)) {
            sb.append('A');
        } else {
            sb.append('-');
        }

        if (isPermitted(i, READ)) {
            sb.append('R');
        } else {
            sb.append('-');
        }

        if (isPermitted(i, WRITE)) {
            sb.append('W');
        } else {
            sb.append('-');
        }

        if (isPermitted(i, CREATE)) {
            sb.append('C');
        } else {
            sb.append('-');
        }

        if (isPermitted(i, DELETE)) {
            sb.append('D');
        } else {
            sb.append('-');
        }

        return sb.toString();
    }
}
