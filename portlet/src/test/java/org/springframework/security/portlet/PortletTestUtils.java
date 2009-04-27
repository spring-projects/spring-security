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

package org.springframework.security.portlet;

import javax.portlet.PortletRequest;

import org.springframework.mock.web.portlet.MockActionRequest;
import org.springframework.mock.web.portlet.MockActionResponse;
import org.springframework.mock.web.portlet.MockPortletRequest;
import org.springframework.mock.web.portlet.MockRenderRequest;
import org.springframework.mock.web.portlet.MockRenderResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

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
        return new User(PortletTestUtils.TESTUSER, "dummy", true, true, true, true,
            AuthorityUtils.createAuthorityList(TESTROLE1, TESTROLE2));
    }

    public static void applyPortletRequestSecurity(MockPortletRequest request) {
        request.setRemoteUser(TESTUSER);
        request.setUserPrincipal(new TestingAuthenticationToken(TESTUSER, TESTCRED));
        request.addUserRole(PORTALROLE1);
        request.addUserRole(PORTALROLE2);
//        request.setAuthType(PortletRequest.FORM_AUTH);
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

    public static PreAuthenticatedAuthenticationToken createToken(PortletRequest request) {
        PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(TESTUSER, TESTCRED);
        token.setDetails(new PortletAuthenticationDetails(request));
        return token;
    }

    public static PreAuthenticatedAuthenticationToken createToken() {
        MockRenderRequest request = createRenderRequest();
        return createToken(request);
    }

    public static PreAuthenticatedAuthenticationToken createAuthenticatedToken(UserDetails user) {
        PreAuthenticatedAuthenticationToken result = new PreAuthenticatedAuthenticationToken(
                user, user.getPassword(), user.getAuthorities());
        result.setAuthenticated(true);
        return result;
    }

    public static PreAuthenticatedAuthenticationToken createAuthenticatedToken() {
        return createAuthenticatedToken(createUser());
    }

}
