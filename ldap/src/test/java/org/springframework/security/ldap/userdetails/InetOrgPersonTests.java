/*
 * Copyright 2002-2016 the original author or authors.
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

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 */
public class InetOrgPersonTests {

	@Test
	public void testUsernameIsMappedFromContextUidIfNotSet() {
		InetOrgPerson.Essence essence = new InetOrgPerson.Essence(createUserContext());
		InetOrgPerson p = (InetOrgPerson) essence.createUserDetails();

		assertThat(p.getUsername()).isEqualTo("ghengis");
	}

	@Test
	public void hashLookupViaEqualObjectRetrievesOriginal() {
		InetOrgPerson.Essence essence = new InetOrgPerson.Essence(createUserContext());
		InetOrgPerson p = (InetOrgPerson) essence.createUserDetails();
		essence = new InetOrgPerson.Essence(createUserContext());
		InetOrgPerson p2 = (InetOrgPerson) essence.createUserDetails();
		Set<InetOrgPerson> set = new HashSet<>();
		set.add(p);
		assertThat(set.contains(p2)).isTrue();
	}

	@Test
	public void usernameIsDifferentFromContextUidIfSet() {
		InetOrgPerson.Essence essence = new InetOrgPerson.Essence(createUserContext());
		essence.setUsername("joe");
		InetOrgPerson p = (InetOrgPerson) essence.createUserDetails();

		assertThat(p.getUsername()).isEqualTo("joe");
		assertThat(p.getUid()).isEqualTo("ghengis");
	}

	@Test
	public void attributesMapCorrectlyFromContext() {
		InetOrgPerson.Essence essence = new InetOrgPerson.Essence(createUserContext());
		InetOrgPerson p = (InetOrgPerson) essence.createUserDetails();

		assertThat(p.getCarLicense()).isEqualTo("HORS1");
		assertThat(p.getMail()).isEqualTo("ghengis@mongolia");
		assertThat(p.getGivenName()).isEqualTo("Ghengis");
		assertThat(p.getSn()).isEqualTo("Khan");
		assertThat(p.getCn()[0]).isEqualTo("Ghengis Khan");
		assertThat(p.getEmployeeNumber()).isEqualTo("00001");
		assertThat(p.getTelephoneNumber()).isEqualTo("+442075436521");
		assertThat(p.getHomePostalAddress()).isEqualTo("Steppes");
		assertThat(p.getHomePhone()).isEqualTo("+467575436521");
		assertThat(p.getO()).isEqualTo("Hordes");
		assertThat(p.getOu()).isEqualTo("Horde1");
		assertThat(p.getPostalAddress()).isEqualTo("On the Move");
		assertThat(p.getPostalCode()).isEqualTo("Changes Frequently");
		assertThat(p.getRoomNumber()).isEqualTo("Yurt 1");
		assertThat(p.getStreet()).isEqualTo("Westward Avenue");
		assertThat(p.getDescription()).isEqualTo("Scary");
		assertThat(p.getDisplayName()).isEqualTo("Ghengis McCann");
		assertThat(p.getInitials()).isEqualTo("G");
	}

	@Test
	public void testPasswordIsSetFromContextUserPassword() {
		InetOrgPerson.Essence essence = new InetOrgPerson.Essence(createUserContext());
		InetOrgPerson p = (InetOrgPerson) essence.createUserDetails();

		assertThat(p.getPassword()).isEqualTo("pillage");
	}

	@Test
	public void mappingBackToContextMatchesOriginalData() {
		DirContextAdapter ctx1 = createUserContext();
		DirContextAdapter ctx2 = new DirContextAdapter();
		ctx1.setAttributeValues("objectclass",
				new String[] { "top", "person", "organizationalPerson", "inetOrgPerson" });
		ctx2.setDn(new DistinguishedName("ignored=ignored"));
		InetOrgPerson p = (InetOrgPerson) (new InetOrgPerson.Essence(ctx1)).createUserDetails();
		p.populateContext(ctx2);

		assertThat(ctx2).isEqualTo(ctx1);
	}

	@Test
	public void copyMatchesOriginalData() {
		DirContextAdapter ctx1 = createUserContext();
		DirContextAdapter ctx2 = new DirContextAdapter();
		ctx2.setDn(new DistinguishedName("ignored=ignored"));
		ctx1.setAttributeValues("objectclass",
				new String[] { "top", "person", "organizationalPerson", "inetOrgPerson" });
		InetOrgPerson p = (InetOrgPerson) (new InetOrgPerson.Essence(ctx1)).createUserDetails();
		InetOrgPerson p2 = (InetOrgPerson) new InetOrgPerson.Essence(p).createUserDetails();
		p2.populateContext(ctx2);

		assertThat(ctx2).isEqualTo(ctx1);
	}

	private DirContextAdapter createUserContext() {
		DirContextAdapter ctx = new DirContextAdapter();

		ctx.setDn(new DistinguishedName("ignored=ignored"));
		ctx.setAttributeValue("uid", "ghengis");
		ctx.setAttributeValue("userPassword", "pillage");
		ctx.setAttributeValue("carLicense", "HORS1");
		ctx.setAttributeValue("cn", "Ghengis Khan");
		ctx.setAttributeValue("description", "Scary");
		ctx.setAttributeValue("destinationIndicator", "West");
		ctx.setAttributeValue("displayName", "Ghengis McCann");
		ctx.setAttributeValue("givenName", "Ghengis");
		ctx.setAttributeValue("homePhone", "+467575436521");
		ctx.setAttributeValue("initials", "G");
		ctx.setAttributeValue("employeeNumber", "00001");
		ctx.setAttributeValue("homePostalAddress", "Steppes");
		ctx.setAttributeValue("mail", "ghengis@mongolia");
		ctx.setAttributeValue("mobile", "always");
		ctx.setAttributeValue("o", "Hordes");
		ctx.setAttributeValue("ou", "Horde1");
		ctx.setAttributeValue("postalAddress", "On the Move");
		ctx.setAttributeValue("postalCode", "Changes Frequently");
		ctx.setAttributeValue("roomNumber", "Yurt 1");
		ctx.setAttributeValue("roomNumber", "Yurt 1");
		ctx.setAttributeValue("sn", "Khan");
		ctx.setAttributeValue("street", "Westward Avenue");
		ctx.setAttributeValue("telephoneNumber", "+442075436521");

		return ctx;
	}

}
