/* Copyright 2004 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sf.acegisecurity.taglibs.authz;

import junit.framework.TestCase;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;


/**
 * DOCUMENT ME!
 *
 * @author Francois Beausoleil
 * @version $Id$
 */
public class AuthorizeTagAttributeTests extends TestCase {
    //~ Instance fields ========================================================

    private final AuthorizeTag authorizeTag = new AuthorizeTag();
    private SecureContextImpl context;
    private TestingAuthenticationToken currentUser;

    //~ Methods ================================================================

    public void testAssertsIfAllGrantedSecond() throws JspException {
        authorizeTag.setIfAllGranted("ROLE_SUPERVISOR,ROLE_SUPERTELLER");
        authorizeTag.setIfAnyGranted("ROLE_RESTRICTED");
        assertEquals("prevents request - principal is missing ROLE_SUPERTELLER",
            Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    public void testAssertsIfAnyGrantedLast() throws JspException {
        authorizeTag.setIfAnyGranted("ROLE_BANKER");
        assertEquals("prevents request - principal is missing ROLE_BANKER",
            Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    public void testAssertsIfNotGrantedFirst() throws JspException {
        authorizeTag.setIfNotGranted("ROLE_RESTRICTED");
        authorizeTag.setIfAllGranted("ROLE_SUPERVISOR,ROLE_RESTRICTED");
        authorizeTag.setIfAnyGranted("ROLE_SUPERVISOR");
        assertEquals("prevents request - principal has ROLE_RESTRICTED",
            Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    protected void setUp() throws Exception {
        super.setUp();

        currentUser = new TestingAuthenticationToken("abc", "123",
                new GrantedAuthority[] {new GrantedAuthorityImpl(
                        "ROLE_SUPERVISOR"), new GrantedAuthorityImpl(
                        "ROLE_RESTRICTED"),});

        context = new SecureContextImpl();
        context.setAuthentication(currentUser);

        ContextHolder.setContext(context);
    }

    protected void tearDown() throws Exception {
        ContextHolder.setContext(null);
    }
}
