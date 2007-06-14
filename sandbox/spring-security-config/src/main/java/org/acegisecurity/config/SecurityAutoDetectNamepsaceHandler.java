/**
 * 
 */
package org.acegisecurity.config;

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

/**
 * @author Vishal Puri
 *
 */
public class SecurityAutoDetectNamepsaceHandler extends NamespaceHandlerSupport {

	/* (non-Javadoc)
	 * @see org.springframework.beans.factory.xml.NamespaceHandler#init()
	 */
	public void init() {
		registerBeanDefinitionParser("autoconfig", new AutoConfigBeanDefinitionParser());
	}

}
