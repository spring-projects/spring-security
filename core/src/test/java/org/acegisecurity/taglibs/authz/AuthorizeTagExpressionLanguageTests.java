package net.sf.acegisecurity.taglibs.authz;

import junit.framework.TestCase;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;
import org.springframework.mock.web.MockPageContext;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;

/**
 * Test case to implement commons-el expression language expansion.
 */
public class AuthorizeTagExpressionLanguageTests extends TestCase {
    //~ Instance fields ========================================================

    private final AuthorizeTag authorizeTag = new AuthorizeTag();
    private SecureContextImpl context;
    private TestingAuthenticationToken currentUser;
    private MockPageContext pageContext;

    //~ Methods ================================================================

    public void testAllGrantedUsesExpressionLanguageWhenExpressionIsEL()
            throws JspException {
        pageContext.setAttribute("authority", "ROLE_TELLER");
        authorizeTag.setIfAllGranted("${authority}");

        assertEquals(
                "allows body - authority var contains ROLE_TELLER",
                Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
    }

    public void testAnyGrantedUsesExpressionLanguageWhenExpressionIsEL()
            throws JspException {
        pageContext.setAttribute("authority", "ROLE_TELLER");
        authorizeTag.setIfAnyGranted("${authority}");

        assertEquals(
                "allows body - authority var contains ROLE_TELLER",
                Tag.EVAL_BODY_INCLUDE, authorizeTag.doStartTag());
    }

    public void testNotGrantedUsesExpressionLanguageWhenExpressionIsEL()
            throws JspException {
        pageContext.setAttribute("authority", "ROLE_TELLER");
        authorizeTag.setIfNotGranted("${authority}");

        assertEquals(
                "allows body - authority var contains ROLE_TELLER",
                Tag.SKIP_BODY, authorizeTag.doStartTag());
    }

    protected void setUp() throws Exception {
        super.setUp();

        pageContext = new MockPageContext();
        authorizeTag.setPageContext(pageContext);

        currentUser = new TestingAuthenticationToken(
                "abc", "123",
                new GrantedAuthority[]{
                    new GrantedAuthorityImpl("ROLE_TELLER"),
                });

        context = new SecureContextImpl();
        context.setAuthentication(currentUser);

        ContextHolder.setContext(context);
    }

    protected void tearDown() throws Exception {
        ContextHolder.setContext(null);
    }
}
