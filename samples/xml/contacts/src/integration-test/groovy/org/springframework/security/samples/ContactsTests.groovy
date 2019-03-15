/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.samples

import geb.spock.*
import spock.lang.Stepwise
import org.springframework.security.samples.pages.*

/**
 * Tests the CAS sample application using service tickets.
 *
 * @author Rob Winch
 */
@Stepwise
class ContactsTests extends GebReportingSpec {
	def 'access home page with unauthenticated user success'() {
		when: 'Unauthenticated user accesses the Home Page'
		to HomePage
		then: 'The page is displayed'
		at HomePage
	}

	def 'access manage page with unauthenticated user sends to login page'() {
		when: 'Unauthenticated user accesses the Manage Page'
		manage.click(LoginPage)
		then: 'The login page is displayed'
		at LoginPage
	}

	def 'authenticated user is sent to original page'() {
		when: 'user authenticates'
		login()
		then: 'The manage page is displayed'
		at ContactsPage
	}

	def 'add contact link works'() {
		when: 'user clicks add link'
		addContact.click(AddPage)
		then: 'The add page is displayed'
		at AddPage
	}

	def 'add contact'() {
		when: 'add a contact'
		addContact
		then: 'The add page is displayed'
		at ContactsPage
		and: 'The new contact is displayed'
		contacts.find { it.email == 'rob@example.com' }?.name ==  'Rob Winch'
	}

	def 'delete contact'() {
		when: 'delete a contact'
		contacts.find { it.email == 'rob@example.com' }.delete()
		then: 'Delete confirmation displayed'
		at DeleteConfirmPage
		when: 'View Manage Page'
		manage.click()
		then: 'New contact has been removed'
		!contacts.find { it.email == 'rob@example.com' }
	}

	def 'authenticated user logs out'() {
		when: 'user logs out'
		logout.click()
		then: 'the default logout success page is displayed'
		at HomePage
		when: 'Unauthenticated user accesses the Manage Page'
		via ContactsPage
		then: 'The login page is displayed'
		at LoginPage
	}
}