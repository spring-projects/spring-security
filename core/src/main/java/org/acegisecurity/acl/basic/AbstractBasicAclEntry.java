/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.acl.basic;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import java.util.Arrays;


/**
 * Abstract implementation of {@link BasicAclEntry}.
 * 
 * <P>
 * Provides core bit mask handling methods.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class AbstractBasicAclEntry implements BasicAclEntry {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(AbstractBasicAclEntry.class);

    //~ Instance fields ========================================================

    private AclObjectIdentity aclObjectIdentity;
    private AclObjectIdentity aclObjectParentIdentity;
    private Object recipient;
    private int[] validPermissions;
    private int mask = 0; // default means no permissions

    //~ Constructors ===========================================================

    public AbstractBasicAclEntry(Object recipient,
        AclObjectIdentity aclObjectIdentity,
        AclObjectIdentity aclObjectParentIdentity, int mask) {
        Assert.notNull(recipient, "recipient cannot be null");

        Assert.notNull(aclObjectIdentity, "aclObjectIdentity cannot be null");

        validPermissions = getValidPermissions();
        Arrays.sort(validPermissions);

        for (int i = 0; i < validPermissions.length; i++) {
            if (logger.isDebugEnabled()) {
                logger.debug("Valid permission:   "
                        + printPermissionsBlock(validPermissions[i]) + " "
                        + printBinary(validPermissions[i]) + " ("
                        + validPermissions[i] + ")");
            }
        }

        this.recipient = recipient;
        this.aclObjectIdentity = aclObjectIdentity;
        this.aclObjectParentIdentity = aclObjectParentIdentity;
        this.mask = mask;
    }

    /**
     * A protected constructor for use by Hibernate.
     */
    protected AbstractBasicAclEntry() {
        validPermissions = getValidPermissions();
        Arrays.sort(validPermissions);
    }

    //~ Methods ================================================================

    public void setAclObjectIdentity(AclObjectIdentity aclObjectIdentity) {
        this.aclObjectIdentity = aclObjectIdentity;
    }

    public AclObjectIdentity getAclObjectIdentity() {
        return this.aclObjectIdentity;
    }

    public void setAclObjectParentIdentity(
        AclObjectIdentity aclObjectParentIdentity) {
        this.aclObjectParentIdentity = aclObjectParentIdentity;
    }

    public AclObjectIdentity getAclObjectParentIdentity() {
        return this.aclObjectParentIdentity;
    }

    /**
     * Subclasses must indicate the permissions they support. Each base
     * permission should be an integer with a base 2. ie: the first permission
     * is 2^^0 (1), the second permission is 2^^1 (1), the third permission is
     * 2^^2 (4) etc. Each base permission should be exposed by the subclass as
     * a <code>public static final int</code>. It is further recommended that
     * valid combinations of permissions are also exposed as <code>public
     * static final int</code>s.
     * 
     * <P>
     * This method returns all permission integers that are allowed to be used
     * together. <B>This must include any combinations of valid
     * permissions</b>. So if the permissions indicated by 2^^2 (4) and 2^^1
     * (2) can be used together, one of the integers returned by this method
     * must be 6 (4 + 2). Otherwise attempts to set the permission will be
     * rejected, as the final resulting mask will be rejected.
     * </p>
     * 
     * <P>
     * Whilst it may seem unduly time onerous to return every valid permission
     * <B>combination</B>, doing so delivers maximum flexibility in ensuring
     * ACLs only reflect logical combinations. For example, it would be
     * inappropriate to grant a "read" and "write" permission along with an
     * "unrestricted" permission, as the latter implies the former
     * permissions.
     * </p>
     *
     * @return <b>every</b> valid combination of permissions
     */
    public abstract int[] getValidPermissions();

    /**
     * Outputs the permissions in a human-friendly format. For example, this
     * method may return "CR-D" to indicate the passed integer permits create,
     * permits read, does not permit update, and permits delete.
     *
     * @param i the integer containing the mask which should be printed
     *
     * @return the human-friend formatted block
     */
    public abstract String printPermissionsBlock(int i);

    public void setMask(int mask) {
        this.mask = mask;
    }

    public int getMask() {
        return this.mask;
    }

    public boolean isPermitted(int permissionToCheck) {
        return isPermitted(this.mask, permissionToCheck);
    }

    public void setRecipient(Object recipient) {
        this.recipient = recipient;
    }

    public Object getRecipient() {
        return this.recipient;
    }

    public int addPermission(int permissionToAdd) {
        return addPermissions(new int[] {permissionToAdd});
    }

    public int addPermissions(int[] permissionsToAdd) {
        if (logger.isDebugEnabled()) {
            logger.debug("BEFORE Permissions: " + printPermissionsBlock(mask)
                + " " + printBinary(mask) + " (" + mask + ")");
        }

        for (int i = 0; i < permissionsToAdd.length; i++) {
            if (logger.isDebugEnabled()) {
                logger.debug("Add     permission: "
                    + printPermissionsBlock(permissionsToAdd[i]) + " "
                    + printBinary(permissionsToAdd[i]) + " ("
                    + permissionsToAdd[i] + ")");
            }

            this.mask |= permissionsToAdd[i];
        }

        if (Arrays.binarySearch(validPermissions, this.mask) < 0) {
            throw new IllegalArgumentException(
                "Resulting permission set will be invalid.");
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("AFTER  Permissions: "
                    + printPermissionsBlock(mask) + " " + printBinary(mask)
                    + " (" + mask + ")");
            }

            return this.mask;
        }
    }

    public int deletePermission(int permissionToDelete) {
        return deletePermissions(new int[] {permissionToDelete});
    }

    public int deletePermissions(int[] permissionsToDelete) {
        if (logger.isDebugEnabled()) {
            logger.debug("BEFORE Permissions: " + printPermissionsBlock(mask)
                + " " + printBinary(mask) + " (" + mask + ")");
        }

        for (int i = 0; i < permissionsToDelete.length; i++) {
            if (logger.isDebugEnabled()) {
                logger.debug("Delete  permission: "
                    + printPermissionsBlock(permissionsToDelete[i]) + " "
                    + printBinary(permissionsToDelete[i]) + " ("
                    + permissionsToDelete[i] + ")");
            }

            this.mask &= ~permissionsToDelete[i];
        }

        if (Arrays.binarySearch(validPermissions, this.mask) < 0) {
            throw new IllegalArgumentException(
                "Resulting permission set will be invalid.");
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug("AFTER  Permissions: "
                    + printPermissionsBlock(mask) + " " + printBinary(mask)
                    + " (" + mask + ")");
            }

            return this.mask;
        }
    }

    /**
     * Outputs the permissions in human-friendly format for the current
     * <code>AbstractBasicAclEntry</code>'s mask.
     *
     * @return the human-friendly formatted block for this instance
     */
    public String printPermissionsBlock() {
        return printPermissionsBlock(this.mask);
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(getClass().getName());
        sb.append("[").append(aclObjectIdentity).append(",").append(recipient);
        sb.append("=").append(printPermissionsBlock(mask)).append(" ");
        sb.append(printBinary(mask)).append(" (");
        sb.append(mask).append(")").append("]");

        return sb.toString();
    }

    public int togglePermission(int permissionToToggle) {
        this.mask ^= permissionToToggle;

        if (Arrays.binarySearch(validPermissions, this.mask) < 0) {
            throw new IllegalArgumentException(
                "Resulting permission set will be invalid.");
        } else {
            return this.mask;
        }
    }

    protected boolean isPermitted(int maskToCheck, int permissionToCheck) {
        return ((maskToCheck & permissionToCheck) == permissionToCheck);
    }

    private String printBinary(int i) {
        String s = Integer.toString(i, 2);

        String pattern = "................................";

        String temp1 = pattern.substring(0, pattern.length() - s.length());

        String temp2 = temp1 + s;

        return temp2.replace('0', '.');
    }
}
