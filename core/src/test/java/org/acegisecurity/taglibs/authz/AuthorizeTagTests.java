/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
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

    public void testUsesAllAuthoritiesToDetermineAccess() {
        authorizeTag.setIfAllGranted("ROLE_SUPERVISOR,ROLE_BANKER");
        authorizeTag.setIfAnyGranted("ROLE_BANKER");
        authorizeTag.setIfNotGranted("ROLE_RESTRICTED");

        currentUser = new TestingAuthenticationToken("abc", "123",
                new GrantedAuthority[] {new GrantedAuthorityImpl(
                        "ROLE_SUPERVISOR"), new GrantedAuthorityImpl(
                        "ROLE_BANKER"), new GrantedAuthorityImpl(
                        "ROLE_RESTRICTED"),});
        context.setAuthentication(currentUser);
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
}
