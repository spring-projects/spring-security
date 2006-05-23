package org.acegisecurity.acls.domain;

import junit.framework.TestCase;

/**
 * Tests BasePermission and CumulativePermission.
 * 
 * @author Ben Alex
 * @version $Id${date}
 *
 */
public class PermissionTests extends TestCase {
	public void testStringConversion() {
		System.out.println("R =  " + BasePermission.READ.toString());
		assertEquals("BasePermission[...............................R=1]", BasePermission.READ.toString());
		
		System.out.println("A =  " + BasePermission.ADMINISTRATION.toString());
		assertEquals("BasePermission[............................A...=8]", BasePermission.ADMINISTRATION.toString());
		
		System.out.println("R =  " + new CumulativePermission().set(BasePermission.READ).toString());
		assertEquals("CumulativePermission[...............................R=1]", new CumulativePermission().set(BasePermission.READ).toString());
		
		System.out.println("A =  " + new CumulativePermission().set(BasePermission.ADMINISTRATION).toString());
		assertEquals("CumulativePermission[............................A...=8]", new CumulativePermission().set(BasePermission.ADMINISTRATION).toString());
		
		System.out.println("RA = " + new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ).toString());
		assertEquals("CumulativePermission[............................A..R=9]", new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ).toString());
		
		System.out.println("R =  " + new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ).clear(BasePermission.ADMINISTRATION).toString());
		assertEquals("CumulativePermission[...............................R=1]", new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ).clear(BasePermission.ADMINISTRATION).toString());
		
		System.out.println("0 =  " + new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ).clear(BasePermission.ADMINISTRATION).clear(BasePermission.READ).toString());
		assertEquals("CumulativePermission[................................=0]", new CumulativePermission().set(BasePermission.ADMINISTRATION).set(BasePermission.READ).clear(BasePermission.ADMINISTRATION).clear(BasePermission.READ).toString());
	}
	
	public void testExpectedIntegerValues() {
		assertEquals(1, BasePermission.READ.getMask());
		assertEquals(8, BasePermission.ADMINISTRATION.getMask());
		assertEquals(9, new CumulativePermission().set(BasePermission.READ).set(BasePermission.ADMINISTRATION).getMask());
	}
}
