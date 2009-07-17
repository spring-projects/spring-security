package org.springframework.security.config.authentication;

import static org.junit.Assert.assertFalse;

import org.junit.Test;
import org.springframework.beans.factory.xml.XmlBeanDefinitionStoreException;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.concurrent.ConcurrentSessionControllerImpl;
import org.springframework.security.authentication.concurrent.SessionRegistryImpl;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.ConfigTestUtils;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.util.FieldUtils;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AuthenticationManagerBeanDefinitionParserTests {
    private AbstractXmlApplicationContext appContext;

    private final String SESSION_CONTROLLER =
        "<b:bean id='sc' class='" + ConcurrentSessionControllerImpl.class.getName() + "'>" +
        "  <b:property name='sessionRegistry'>" +
        "      <b:bean class='" + SessionRegistryImpl.class.getName() + "'/>" +
        "  </b:property>" +
        "</b:bean>";

    @Test
    public void sessionControllerRefAttributeIsSupportedFor204ContextButHasNoEffect() throws Exception {
        setContext(
          "<http auto-config='true'/>" +
          SESSION_CONTROLLER +
          "<authentication-manager alias='authManager' session-controller-ref='sc'/>" +
          ConfigTestUtils.AUTH_PROVIDER_XML, "2.0.4");
        ProviderManager pm = (ProviderManager) appContext.getBean(BeanIds.AUTHENTICATION_MANAGER);
        assertFalse(FieldUtils.getFieldValue(pm, "sessionController") instanceof ConcurrentSessionControllerImpl);
    }

    @Test(expected=XmlBeanDefinitionStoreException.class)
    public void sessionControllerRefAttributeIsRejectedFor30Context() throws Exception {
        setContext(
          "<http auto-config='true'/>" +
          SESSION_CONTROLLER +
          "<authentication-manager alias='authManager' session-controller-ref='sc'/>" +
          ConfigTestUtils.AUTH_PROVIDER_XML, "3.0");
        appContext.getBean(BeanIds.AUTHENTICATION_MANAGER);
    }

    private void setContext(String context, String version) {
        appContext = new InMemoryXmlApplicationContext(context, version, null);
    }
}
