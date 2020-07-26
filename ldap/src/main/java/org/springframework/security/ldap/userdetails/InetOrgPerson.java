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
package org.springframework.security.ldap.userdetails;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * UserDetails implementation whose properties are based on a subset of the LDAP schema
 * for <tt>inetOrgPerson</tt>.
 *
 * <p>
 * The username will be mapped from the <tt>uid</tt> attribute by default.
 *
 * @author Luke
 */
public class InetOrgPerson extends Person {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private String carLicense;

	// Person.cn
	private String destinationIndicator;

	private String departmentNumber;

	// Person.description
	private String displayName;

	private String employeeNumber;

	private String homePhone;

	private String homePostalAddress;

	private String initials;

	private String mail;

	private String mobile;

	private String o;

	private String ou;

	private String postalAddress;

	private String postalCode;

	private String roomNumber;

	private String street;

	// Person.sn
	// Person.telephoneNumber
	private String title;

	private String uid;

	public String getUid() {
		return this.uid;
	}

	public String getMail() {
		return this.mail;
	}

	public String getEmployeeNumber() {
		return this.employeeNumber;
	}

	public String getInitials() {
		return this.initials;
	}

	public String getDestinationIndicator() {
		return this.destinationIndicator;
	}

	public String getO() {
		return this.o;
	}

	public String getOu() {
		return this.ou;
	}

	public String getTitle() {
		return this.title;
	}

	public String getCarLicense() {
		return this.carLicense;
	}

	public String getDepartmentNumber() {
		return this.departmentNumber;
	}

	public String getDisplayName() {
		return this.displayName;
	}

	public String getHomePhone() {
		return this.homePhone;
	}

	public String getRoomNumber() {
		return this.roomNumber;
	}

	public String getHomePostalAddress() {
		return this.homePostalAddress;
	}

	public String getMobile() {
		return this.mobile;
	}

	public String getPostalAddress() {
		return this.postalAddress;
	}

	public String getPostalCode() {
		return this.postalCode;
	}

	public String getStreet() {
		return this.street;
	}

	@Override
	protected void populateContext(DirContextAdapter adapter) {
		super.populateContext(adapter);
		adapter.setAttributeValue("carLicense", this.carLicense);
		adapter.setAttributeValue("departmentNumber", this.departmentNumber);
		adapter.setAttributeValue("destinationIndicator", this.destinationIndicator);
		adapter.setAttributeValue("displayName", this.displayName);
		adapter.setAttributeValue("employeeNumber", this.employeeNumber);
		adapter.setAttributeValue("homePhone", this.homePhone);
		adapter.setAttributeValue("homePostalAddress", this.homePostalAddress);
		adapter.setAttributeValue("initials", this.initials);
		adapter.setAttributeValue("mail", this.mail);
		adapter.setAttributeValue("mobile", this.mobile);
		adapter.setAttributeValue("postalAddress", this.postalAddress);
		adapter.setAttributeValue("postalCode", this.postalCode);
		adapter.setAttributeValue("ou", this.ou);
		adapter.setAttributeValue("o", this.o);
		adapter.setAttributeValue("roomNumber", this.roomNumber);
		adapter.setAttributeValue("street", this.street);
		adapter.setAttributeValue("uid", this.uid);
		adapter.setAttributeValues("objectclass",
				new String[] { "top", "person", "organizationalPerson", "inetOrgPerson" });
	}

	public static class Essence extends Person.Essence {

		public Essence() {
		}

		public Essence(InetOrgPerson copyMe) {
			super(copyMe);
			setCarLicense(copyMe.getCarLicense());
			setDepartmentNumber(copyMe.getDepartmentNumber());
			setDestinationIndicator(copyMe.getDestinationIndicator());
			setDisplayName(copyMe.getDisplayName());
			setEmployeeNumber(copyMe.getEmployeeNumber());
			setHomePhone(copyMe.getHomePhone());
			setHomePostalAddress(copyMe.getHomePostalAddress());
			setInitials(copyMe.getInitials());
			setMail(copyMe.getMail());
			setMobile(copyMe.getMobile());
			setO(copyMe.getO());
			setOu(copyMe.getOu());
			setPostalAddress(copyMe.getPostalAddress());
			setPostalCode(copyMe.getPostalCode());
			setRoomNumber(copyMe.getRoomNumber());
			setStreet(copyMe.getStreet());
			setTitle(copyMe.getTitle());
			setUid(copyMe.getUid());
		}

		public Essence(DirContextOperations ctx) {
			super(ctx);
			setCarLicense(ctx.getStringAttribute("carLicense"));
			setDepartmentNumber(ctx.getStringAttribute("departmentNumber"));
			setDestinationIndicator(ctx.getStringAttribute("destinationIndicator"));
			setDisplayName(ctx.getStringAttribute("displayName"));
			setEmployeeNumber(ctx.getStringAttribute("employeeNumber"));
			setHomePhone(ctx.getStringAttribute("homePhone"));
			setHomePostalAddress(ctx.getStringAttribute("homePostalAddress"));
			setInitials(ctx.getStringAttribute("initials"));
			setMail(ctx.getStringAttribute("mail"));
			setMobile(ctx.getStringAttribute("mobile"));
			setO(ctx.getStringAttribute("o"));
			setOu(ctx.getStringAttribute("ou"));
			setPostalAddress(ctx.getStringAttribute("postalAddress"));
			setPostalCode(ctx.getStringAttribute("postalCode"));
			setRoomNumber(ctx.getStringAttribute("roomNumber"));
			setStreet(ctx.getStringAttribute("street"));
			setTitle(ctx.getStringAttribute("title"));
			setUid(ctx.getStringAttribute("uid"));
		}

		@Override
		protected LdapUserDetailsImpl createTarget() {
			return new InetOrgPerson();
		}

		public void setMail(String email) {
			((InetOrgPerson) this.instance).mail = email;
		}

		public void setUid(String uid) {
			((InetOrgPerson) this.instance).uid = uid;

			if (this.instance.getUsername() == null) {
				setUsername(uid);
			}
		}

		public void setInitials(String initials) {
			((InetOrgPerson) this.instance).initials = initials;
		}

		public void setO(String organization) {
			((InetOrgPerson) this.instance).o = organization;
		}

		public void setOu(String ou) {
			((InetOrgPerson) this.instance).ou = ou;
		}

		public void setRoomNumber(String no) {
			((InetOrgPerson) this.instance).roomNumber = no;
		}

		public void setTitle(String title) {
			((InetOrgPerson) this.instance).title = title;
		}

		public void setCarLicense(String carLicense) {
			((InetOrgPerson) this.instance).carLicense = carLicense;
		}

		public void setDepartmentNumber(String departmentNumber) {
			((InetOrgPerson) this.instance).departmentNumber = departmentNumber;
		}

		public void setDisplayName(String displayName) {
			((InetOrgPerson) this.instance).displayName = displayName;
		}

		public void setEmployeeNumber(String no) {
			((InetOrgPerson) this.instance).employeeNumber = no;
		}

		public void setDestinationIndicator(String destination) {
			((InetOrgPerson) this.instance).destinationIndicator = destination;
		}

		public void setHomePhone(String homePhone) {
			((InetOrgPerson) this.instance).homePhone = homePhone;
		}

		public void setStreet(String street) {
			((InetOrgPerson) this.instance).street = street;
		}

		public void setPostalCode(String postalCode) {
			((InetOrgPerson) this.instance).postalCode = postalCode;
		}

		public void setPostalAddress(String postalAddress) {
			((InetOrgPerson) this.instance).postalAddress = postalAddress;
		}

		public void setMobile(String mobile) {
			((InetOrgPerson) this.instance).mobile = mobile;
		}

		public void setHomePostalAddress(String homePostalAddress) {
			((InetOrgPerson) this.instance).homePostalAddress = homePostalAddress;
		}

	}

}
