/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.context.HttpSessionContextIntegrationFilter;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.core.Conventions;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;

/**
 * 
 * @author vpuri
 * 
 */
public class ContextIntegrationBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {
	
	private static final String HTTP_SESSION_CONTEXT_INTEGRATION = "session-context-integration";
	
	private static final String SESSION_CREATION = "sessionCreation";
	
	

	private static final String IF_REQUIRED = "ifRequired";

	private static final String ALWAYS = "always";

	private static final String NEVER = "never";

	
	
	protected Class getBeanClass(Element element) {
		return HttpSessionContextIntegrationFilter.class;
	}
	
	

	protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
		
		NamedNodeMap attributes = element.getAttributes();
		
		for (int x = 0; x < attributes.getLength(); x++) {
			Attr attribute = (Attr) attributes.item(x);
			String attributeName = attribute.getLocalName();
			if ( !ID_ATTRIBUTE.equals(attributeName)) {
				if (attributeName.equals(SESSION_CREATION)) {
					String sessionCreation = element.getAttribute(SESSION_CREATION);
					
					if(sessionCreation.equals(IF_REQUIRED)) {
						builder.addPropertyValue("allowSessionCreation", Boolean.TRUE);
					}
					
					if(sessionCreation.equals(ALWAYS)) {
						builder.addPropertyValue("allowSessionCreation", Boolean.TRUE);
					}
					
					if(sessionCreation.equals(NEVER)) {
						builder.addPropertyValue("allowSessionCreation", Boolean.FALSE);
					}
				}
				else{			
					String propertyName = Conventions.attributeNameToPropertyName(attributeName);
					Assert.state(StringUtils.hasText(propertyName),
							"Illegal property name returned from 'extractPropertyName(String)': cannot be null or empty.");
					builder.addPropertyValue(propertyName, attribute.getValue());			
				}
			}
		}	
	}
}

	
