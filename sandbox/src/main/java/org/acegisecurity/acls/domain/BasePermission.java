package org.acegisecurity.acls.domain;

import org.acegisecurity.acls.AclFormattingUtils;
import org.acegisecurity.acls.Permission;

public class BasePermission implements Permission {
	public static final Permission READ = new BasePermission(1<<0, 'R'); // 1
	public static final Permission WRITE = new BasePermission(1<<1, 'W'); // 2
	public static final Permission CREATE = new BasePermission(1<<2, 'C'); // 4
	public static final Permission ADMINISTRATION = new BasePermission(1<<3, 'A'); // 8
	
	private int mask;
	private char code;
	
	private BasePermission(int mask, char code) {
		this.mask = mask;
		this.code = code;
	}
	
	public boolean equals(Object arg0) {
		if (!(arg0 instanceof BasePermission)) {
			return false;
		}
		BasePermission rhs = (BasePermission) arg0;
		return (this.mask == rhs.getMask());
	}

	/**
	 * Dynamically creates a <code>CumulativePermission</code>
	 * representing the active bits in the passed mask.
	 * NB: Only uses <code>BasePermission</code>!
	 * 
	 * @param mask to review
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
			permission.set(ADMINISTRATION);
		}
		return permission;
	}
	
	public int getMask() {
		return mask;
	}

	public String toString() {
		return "BasePermission[" + getPattern() + "=" + mask + "]";
	}

	public String getPattern() {
		return AclFormattingUtils.printBinary(mask, code);
	}

}
