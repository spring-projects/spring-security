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

import java.util.Objects;

import org.jspecify.annotations.Nullable;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.util.Assert;

/**
 * UserDetails implementation whose properties are based on a subset of the LDAP schema
 * for <tt>inetOrgPerson</tt>.
 *
 * <p>
 * The username will be mapped from the <tt>uid</tt> attribute by default.
 *
 * @author Luke Taylor
 */
public class InetOrgPerson extends Person {

	private static final long serialVersionUID = 620L;

	private @Nullable String carLicense;

	// Person.cn
	private @Nullable String destinationIndicator;

	private @Nullable String departmentNumber;

	// Person.description
	private @Nullable String displayName;

	private @Nullable String employeeNumber;

	private @Nullable String homePhone;

	private @Nullable String homePostalAddress;

	private @Nullable String initials;

	private @Nullable String mail;

	private @Nullable String mobile;

	private @Nullable String o;

	private @Nullable String ou;

	private @Nullable String postalAddress;

	private @Nullable String postalCode;

	private @Nullable String roomNumber;

	private @Nullable String street;

	// Person.sn
	// Person.telephoneNumber
	private @Nullable String title;

	private @Nullable String uid;

	public String getUid() {
		return Objects.requireNonNull(this.uid, "uid cannot be null");
	}

	public @Nullable String getMail() {
		return this.mail;
	}

	public @Nullable String getEmployeeNumber() {
		return this.employeeNumber;
	}

	public @Nullable String getInitials() {
		return this.initials;
	}

	public @Nullable String getDestinationIndicator() {
		return this.destinationIndicator;
	}

	public @Nullable String getO() {
		return this.o;
	}

	public @Nullable String getOu() {
		return this.ou;
	}

	public @Nullable String getTitle() {
		return this.title;
	}

	public @Nullable String getCarLicense() {
		return this.carLicense;
	}

	public @Nullable String getDepartmentNumber() {
		return this.departmentNumber;
	}

	public @Nullable String getDisplayName() {
		return this.displayName;
	}

	public @Nullable String getHomePhone() {
		return this.homePhone;
	}

	public @Nullable String getRoomNumber() {
		return this.roomNumber;
	}

	public @Nullable String getHomePostalAddress() {
		return this.homePostalAddress;
	}

	public @Nullable String getMobile() {
		return this.mobile;
	}

	public @Nullable String getPostalAddress() {
		return this.postalAddress;
	}

	public @Nullable String getPostalCode() {
		return this.postalCode;
	}

	public @Nullable String getStreet() {
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

		private @Nullable String username;

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
			String uid = ctx.getStringAttribute("uid");
			Assert.notNull(uid, "uid cannot be null");
			setUid(uid);
		}

		@Override
		protected LdapUserDetailsImpl createTarget() {
			return new InetOrgPerson();
		}

		public void setMail(@Nullable String email) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).mail = email;
		}

		public void setUid(String uid) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).uid = uid;

			if (this.username == null) {
				setUsername(uid);
			}
		}

		public void setUsername(String username) {
			super.setUsername(username);
			this.username = username;
		}

		public void setInitials(@Nullable String initials) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).initials = initials;
		}

		public void setO(@Nullable String organization) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).o = organization;
		}

		public void setOu(@Nullable String ou) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).ou = ou;
		}

		public void setRoomNumber(@Nullable String no) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).roomNumber = no;
		}

		public void setTitle(@Nullable String title) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).title = title;
		}

		public void setCarLicense(@Nullable String carLicense) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).carLicense = carLicense;
		}

		public void setDepartmentNumber(@Nullable String departmentNumber) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).departmentNumber = departmentNumber;
		}

		public void setDisplayName(@Nullable String displayName) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).displayName = displayName;
		}

		public void setEmployeeNumber(@Nullable String no) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).employeeNumber = no;
		}

		public void setDestinationIndicator(@Nullable String destination) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).destinationIndicator = destination;
		}

		public void setHomePhone(@Nullable String homePhone) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).homePhone = homePhone;
		}

		public void setStreet(@Nullable String street) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).street = street;
		}

		public void setPostalCode(@Nullable String postalCode) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).postalCode = postalCode;
		}

		public void setPostalAddress(@Nullable String postalAddress) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).postalAddress = postalAddress;
		}

		public void setMobile(@Nullable String mobile) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).mobile = mobile;
		}

		public void setHomePostalAddress(@Nullable String homePostalAddress) {
			Assert.notNull(this.instance, "Essence can only be used to create a single instance");
			((InetOrgPerson) this.instance).homePostalAddress = homePostalAddress;
		}

	}

}
