/*
 * Copyright 2005-2007 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.providers.portlet;

import javax.portlet.PortletRequest;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.context.SecurityContext;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.context.SecurityContextImpl;
import org.acegisecurity.providers.TestingAuthenticationToken;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.springframework.mock.web.portlet.MockActionRequest;
import org.springframework.mock.web.portlet.MockActionResponse;
import org.springframework.mock.web.portlet.MockPortletRequest;
import org.springframework.mock.web.portlet.MockRenderRequest;
import org.springframework.mock.web.portlet.MockRenderResponse;

/**
 * Utilities for testing Portlet (JSR 168) based security.
 *
 * @author John A. Lewis
 * @since 2.0
 * @version $Id$
 */
public class PortletTestUtils {

	//~ Static fields/initializers =====================================================================================

	public static final String PORTALROLE1 = "ONE";
	public static final String PORTALROLE2 = "TWO";

	public static final String TESTUSER = "testuser";
	public static final String TESTCRED = PortletRequest.FORM_AUTH;
	public static final String TESTROLE1 = "ROLE_" + PORTALROLE1;
	public static final String TESTROLE2 = "ROLE_" + PORTALROLE2;

	//~ Methods ========================================================================================================

	public static UserDetails createUser() {
		return new User(PortletTestUtils.TESTUSER, PortletTestUtils.TESTCRED, true, true, true, true,
			new GrantedAuthority[] {new GrantedAuthorityImpl(TESTROLE1), new GrantedAuthorityImpl(TESTROLE2)});
	}

    public static void applyPortletRequestSecurity(MockPortletRequest request) {
		request.setRemoteUser(TESTUSER);
		request.setUserPrincipal(new TestingAuthenticationToken(TESTUSER, TESTCRED, null));
		request.addUserRole(PORTALROLE1);
		request.addUserRole(PORTALROLE2);
		request.setAuthType(PortletRequest.FORM_AUTH);
    }

    public static MockRenderRequest createRenderRequest() {
		MockRenderRequest request = new MockRenderRequest();
		applyPortletRequestSecurity(request);
		return request;
    }

    public static MockRenderResponse createRenderResponse() {
		MockRenderResponse response = new MockRenderResponse();
		return response;
    }

    public static MockActionRequest createActionRequest() {
    	MockActionRequest request = new MockActionRequest();
		applyPortletRequestSecurity(request);
		return request;
    }

    public static MockActionResponse createActionResponse() {
    	MockActionResponse response = new MockActionResponse();
		return response;
    }

	public static PortletAuthenticationToken createToken(PortletRequest request) {
		PortletAuthenticationToken token = new PortletAuthenticationToken(TESTUSER, TESTCRED, null);
		token.setDetails(request);
		return token;
	}

	public static PortletAuthenticationToken createToken() {
		MockRenderRequest request = createRenderRequest();
		return createToken(request);
	}

	public static PortletAuthenticationToken createAuthenticatedToken(UserDetails user) {
		PortletAuthenticationToken result = new PortletAuthenticationToken(
				user, user.getPassword(), user.getAuthorities());
		result.setAuthenticated(true);
		return result;
	}
	public static PortletAuthenticationToken createAuthenticatedToken() {
		return createAuthenticatedToken(createUser());
	}

    public static void setupSecurityContext(PortletRequest request) {
		PortletAuthenticationToken token = createToken(request);
		SecurityContext context = new SecurityContextImpl();
		context.setAuthentication(token);
		SecurityContextHolder.setContext(context);
    }

    public static void setupSecurityContext() {
		MockRenderRequest request = createRenderRequest();
		setupSecurityContext(request);
    }

    public static void cleanupSecurityContext() {
		SecurityContextHolder.clearContext();
    }

}
