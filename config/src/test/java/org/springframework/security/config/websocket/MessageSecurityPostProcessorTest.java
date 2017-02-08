package org.springframework.security.config.websocket;

import org.junit.Test;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.GenericBeanDefinition;
import org.springframework.beans.factory.support.SimpleBeanDefinitionRegistry;

public class MessageSecurityPostProcessorTest {

	private WebSocketMessageBrokerSecurityBeanDefinitionParser.MessageSecurityPostProcessor postProcessor =
		new WebSocketMessageBrokerSecurityBeanDefinitionParser.MessageSecurityPostProcessor("id", false);

	@Test
	public void handlesBeansWithoutClass() {
		BeanDefinitionRegistry registry = new SimpleBeanDefinitionRegistry();
		registry.registerBeanDefinition("beanWithoutClass", new GenericBeanDefinition());
		postProcessor.postProcessBeanDefinitionRegistry(registry);
	}
}
