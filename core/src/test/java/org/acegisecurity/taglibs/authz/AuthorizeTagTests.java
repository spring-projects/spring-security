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
public class AuthorizeTagTests extends TestCase {
    //~ Instance fields ========================================================

    private final AuthorizeTag authorizeTag = new AuthorizeTag();
    private SecureContextImpl context;
    private TestingAuthenticationToken currentUser;

    //~ Methods ================================================================

    public void testAlwaysReturnsUnauthorizedIfNoUserFound()
        throws JspException {
        context.setAuthentication(null);

        authorizeTag.setIfAllGranted("ROLE_TELLER");
        assertEquals("prevents request - no principal in Context",
            Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    public void testDefaultsToNotOutputtingBodyWhenNoRequiredAuthorities()
        throws JspException {
        assertEquals("", authorizeTag.getIfAllGranted());
        assertEquals("", authorizeTag.getIfAnyGranted());
        assertEquals("", authorizeTag.getIfNotGranted());

        assertEquals("prevents body output - no authorities granted",
            Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    public void testOutputsBodyIfOneRolePresent() throws JspException {
        authorizeTag.setIfAnyGranted("ROLE_TELLER");
        assertEquals("authorized - ROLE_TELLER in both sets",
            Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
    }

    public void testOutputsBodyWhenAllGranted() throws JspException {
        authorizeTag.setIfAllGranted("ROLE_SUPERVISOR,ROLE_TELLER");
        assertEquals("allows request - all required roles granted on principal",
            Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
    }

    public void testOutputsBodyWhenNotGrantedSatisfied()
        throws JspException {
        authorizeTag.setIfNotGranted("ROLE_BANKER");
        assertEquals("allows request - principal doesn't have ROLE_BANKER",
            Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
    }

    public void testPreventsBodyOutputIfNoSecureContext()
        throws JspException {
        ContextHolder.setContext(null);
        authorizeTag.setIfAnyGranted("ROLE_BANKER");

        assertEquals("prevents output - no context defined", Tag.SKIP_BODY,
            authorizeTag.doStartTag());
    }

    public void testSkipsBodyIfNoAnyRolePresent() throws JspException {
        authorizeTag.setIfAnyGranted("ROLE_BANKER");
        assertEquals("unauthorized - ROLE_BANKER not in granted authorities",
            Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    public void testSkipsBodyWhenMissingAnAllGranted()
        throws JspException {
        authorizeTag.setIfAllGranted("ROLE_SUPERVISOR,ROLE_TELLER,ROLE_BANKER");
        assertEquals("prevents request - missing ROLE_BANKER on principal",
            Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    public void testSkipsBodyWhenNotGrantedUnsatisfied()
        throws JspException {
        authorizeTag.setIfNotGranted("ROLE_TELLER");
        assertEquals("prevents request - principal has ROLE_TELLER",
            Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    protected void setUp() throws Exception {
        super.setUp();

        currentUser = new TestingAuthenticationToken("abc", "123",
                new GrantedAuthority[] {new GrantedAuthorityImpl(
                        "ROLE_SUPERVISOR"), new GrantedAuthorityImpl(
                        "ROLE_TELLER"),});

        context = new SecureContextImpl();
        context.setAuthentication(currentUser);

        ContextHolder.setContext(context);
    }

    protected void tearDown() throws Exception {
        ContextHolder.setContext(null);
    }
}
