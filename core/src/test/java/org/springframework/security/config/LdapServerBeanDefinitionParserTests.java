package org.springframework.security.config;

import org.junit.After;
import org.junit.Test;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.util.InMemoryXmlApplicationContext;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapServerBeanDefinitionParserTests {
    InMemoryXmlApplicationContext appCtx;

    @After
    public void closeAppContext() {
        if (appCtx != null) {
            appCtx.close();
            appCtx = null;
        }
    }

    @Test
    public void embeddedServerCreationContainsExpectedContextSourceAndData() {
        appCtx = new InMemoryXmlApplicationContext("<ldap-server />");

        DefaultSpringSecurityContextSource contextSource = (DefaultSpringSecurityContextSource) appCtx.getBean(BeanIds.CONTEXT_SOURCE);

        // Check data is loaded
        LdapTemplate template = new LdapTemplate(contextSource);
        template.lookup("uid=ben,ou=people");
    }

    @Test
    public void useOfUrlAttributeCreatesCorrectContextSource() {
        // Create second "server" with a url pointing at embedded one
        appCtx = new InMemoryXmlApplicationContext("<ldap-server port='33388'/>" +
                "<ldap-server id='blah' url='ldap://127.0.0.1:33388/dc=springframework,dc=org' />");

        // Check the default context source is still there.
        appCtx.getBean(BeanIds.CONTEXT_SOURCE);

        DefaultSpringSecurityContextSource contextSource = (DefaultSpringSecurityContextSource) appCtx.getBean("blah");

        // Check data is loaded as before
        LdapTemplate template = new LdapTemplate(contextSource);
        template.lookup("uid=ben,ou=people");
    }

    @Test
    public void loadingSpecificLdifFileIsSuccessful() {
        appCtx = new InMemoryXmlApplicationContext(
                "<ldap-server ldif='classpath*:test-server2.xldif' root='dc=monkeymachine,dc=co,dc=uk' />");
        DefaultSpringSecurityContextSource contextSource = (DefaultSpringSecurityContextSource) appCtx.getBean(BeanIds.CONTEXT_SOURCE);

        LdapTemplate template = new LdapTemplate(contextSource);
        template.lookup("uid=pg,ou=gorillas");
    }



}
