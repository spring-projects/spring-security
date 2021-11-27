/*
 * Copyright 2002-2013 the original author or authors.
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

import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
public class SpringSecurityLdapTemplateTests {

	@Mock
	private DirContext ctx;

	@Captor
	private ArgumentCaptor<SearchControls> searchControls;

	@Mock
	private NamingEnumeration<SearchResult> resultsEnum;

	@Mock
	private SearchResult searchResult;

	// SEC-2405
	@Test
	public void searchForSingleEntryInternalAllowsReferrals() throws Exception {
		String base = "";
		String filter = "";
		String searchResultName = "ldap://example.com/dc=springframework,dc=org";
		Object[] params = new Object[] {};
		DirContextAdapter searchResultObject = mock(DirContextAdapter.class);
		given(this.ctx.search(any(DistinguishedName.class), eq(filter), eq(params), this.searchControls.capture()))
				.willReturn(this.resultsEnum);
		given(this.resultsEnum.hasMore()).willReturn(true, false);
		given(this.resultsEnum.next()).willReturn(this.searchResult);
		given(this.searchResult.getObject()).willReturn(searchResultObject);
		SpringSecurityLdapTemplate.searchForSingleEntryInternal(this.ctx, mock(SearchControls.class), base, filter,
				params);
		assertThat(this.searchControls.getValue().getReturningObjFlag()).isTrue();
	}

}
