/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.ldap;

import java.util.Set;

import javax.naming.Name;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.support.LdapNameBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class SpringSecurityLdapTemplateTests {

	private static final String BASE_DN = "dc=springframework,dc=org";

	@Mock
	private DirContext ctx;

	@Mock
	private ContextSource contextSource;

	@Captor
	private ArgumentCaptor<SearchControls> searchControls;

	@Mock
	private NamingEnumeration<SearchResult> resultsEnum;

	@Mock
	private SearchResult searchResult;

	@Test
	public void searchForSingleEntryUsesReturnObjFalseByDefault() throws Exception {
		given(this.contextSource.getReadOnlyContext()).willReturn(this.ctx);
		given(this.ctx.getNameInNamespace()).willReturn(BASE_DN);
		given(this.searchResult.getNameInNamespace()).willReturn("uid=bob,ou=people," + BASE_DN);
		given(this.searchResult.getAttributes()).willReturn(attributes("uid", "bob", "cn", "Bob Hamilton"));
		given(this.ctx.search(any(Name.class), eq("(uid={0})"), any(Object[].class), this.searchControls.capture()))
			.willReturn(this.resultsEnum);
		given(this.resultsEnum.hasMore()).willReturn(true, false);
		given(this.resultsEnum.next()).willReturn(this.searchResult);

		SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(this.contextSource);
		DirContextOperations result = template.searchForSingleEntry("ou=people", "(uid={0})", new Object[] { "bob" });

		assertThat(this.searchControls.getValue().getReturningObjFlag()).isFalse();
		assertThat(result.getNameInNamespace()).isEqualTo("uid=bob,ou=people," + BASE_DN);
		assertThat(result.getStringAttribute("cn")).isEqualTo("Bob Hamilton");
		verify(this.searchResult, never()).getObject();
	}

	@Test
	public void searchForSingleEntryUsesReturnObjWhenExplicitlyEnabled() throws Exception {
		given(this.contextSource.getReadOnlyContext()).willReturn(this.ctx);
		given(this.ctx.getNameInNamespace()).willReturn(BASE_DN);
		given(this.ctx.search(any(Name.class), eq("(uid={0})"), any(Object[].class), this.searchControls.capture()))
			.willReturn(this.resultsEnum);
		given(this.resultsEnum.hasMore()).willReturn(true, false);
		given(this.resultsEnum.next()).willReturn(this.searchResult);
		DirContextAdapter searchResultObject = mock(DirContextAdapter.class);
		given(this.searchResult.getObject()).willReturn(searchResultObject);

		SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(this.contextSource);
		SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		controls.setReturningObjFlag(true);
		template.setSearchControls(controls);
		DirContextOperations result = template.searchForSingleEntry("ou=people", "(uid={0})", new Object[] { "bob" });

		assertThat(this.searchControls.getValue().getReturningObjFlag()).isTrue();
		assertThat(result).isSameAs(searchResultObject);
	}

	@Test
	public void searchForSingleAttributeValuesUsesReturnObjFalseByDefault() throws Exception {
		given(this.contextSource.getReadOnlyContext()).willReturn(this.ctx);
		SearchResult developer = result("cn=developer,ou=groups," + BASE_DN, attributes("cn", "developer"));
		SearchResult manager = result("cn=manager,ou=groups," + BASE_DN, attributes("cn", "manager"));
		given(this.ctx.search(eq("ou=groups"), anyString(), this.searchControls.capture()))
			.willReturn(this.resultsEnum);
		given(this.resultsEnum.hasMore()).willReturn(true, true, false);
		given(this.resultsEnum.next()).willReturn(developer, manager);

		SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(this.contextSource);
		Set<String> values = template.searchForSingleAttributeValues("ou=groups", "(member={0})",
				new Object[] { "uid=ben,ou=people," + BASE_DN }, "cn");

		assertThat(this.searchControls.getValue().getReturningObjFlag()).isFalse();
		assertThat(values).containsExactlyInAnyOrder("developer", "manager");
	}

	@Test
	public void searchForSingleAttributeValuesUsesReturnObjWhenExplicitlyEnabled() throws Exception {
		given(this.contextSource.getReadOnlyContext()).willReturn(this.ctx);
		SearchResult developer = mock(SearchResult.class);
		DirContextAdapter adapter = new DirContextAdapter(attributes("cn", "developer"),
				LdapNameBuilder.newInstance("cn=developer,ou=groups," + BASE_DN).build());
		given(developer.getObject()).willReturn(adapter);
		given(this.ctx.search(eq("ou=groups"), anyString(), this.searchControls.capture()))
			.willReturn(this.resultsEnum);
		given(this.resultsEnum.hasMore()).willReturn(true, false);
		given(this.resultsEnum.next()).willReturn(developer);

		SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(this.contextSource);
		SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		controls.setReturningObjFlag(true);
		template.setSearchControls(controls);
		Set<String> values = template.searchForSingleAttributeValues("ou=groups", "(member={0})",
				new Object[] { "uid=ben,ou=people," + BASE_DN }, "cn");

		assertThat(this.searchControls.getValue().getReturningObjFlag()).isTrue();
		assertThat(values).containsExactly("developer");
	}

	private static SearchResult result(String nameInNamespace, Attributes attributes) {
		SearchResult result = new SearchResult(nameInNamespace, null, attributes);
		result.setNameInNamespace(nameInNamespace);
		return result;
	}

	private static Attributes attributes(String... nameValues) {
		Attributes attributes = new BasicAttributes(true);
		for (int i = 0; i < nameValues.length; i += 2) {
			attributes.put(new BasicAttribute(nameValues[i], nameValues[i + 1]));
		}
		return attributes;
	}

}
