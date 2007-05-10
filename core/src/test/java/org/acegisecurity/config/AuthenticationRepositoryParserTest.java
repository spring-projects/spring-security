/**
 * 
 */
package org.acegisecurity.config;

import junit.framework.TestCase;

import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.dao.DaoAuthenticationProvider;
import org.acegisecurity.providers.dao.SaltSource;
import org.acegisecurity.providers.encoding.Md5PasswordEncoder;
import org.acegisecurity.providers.encoding.PasswordEncoder;
import org.acegisecurity.providers.encoding.PlaintextPasswordEncoder;
import org.acegisecurity.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.util.Assert;

/**
 * @author vpuri
 *
 */
public class AuthenticationRepositoryParserTest extends TestCase {
	
	public void testAuthenticationRepositoryDefaultWithAutoUserdetails() {
		ApplicationContext context = new ClassPathXmlApplicationContext("org/acegisecurity/config/authentication-dao-defaults.xml");
		ConfigurableListableBeanFactory clbf = 
			(ConfigurableListableBeanFactory)context.getAutowireCapableBeanFactory();
		
		String[] names = clbf.getBeanNamesForType(AuthenticationProvider.class);
		assertEquals(1, names.length);
		
		// check bean class
		RootBeanDefinition definition = (RootBeanDefinition)clbf.getBeanDefinition(names[0]);
	    assertEquals(DaoAuthenticationProvider.class, definition.getBeanClass());
		
		DaoAuthenticationProvider provider = (DaoAuthenticationProvider)context.getBean("authenticationRepository");
		Assert.isAssignable(JdbcDaoImpl.class, provider.getUserDetailsService().getClass());
		
	}
	
	public void testCollaboratorsAsInnerBeans(){
		ApplicationContext context = new ClassPathXmlApplicationContext("org/acegisecurity/config/authentication-innerbeans.xml");
		ConfigurableListableBeanFactory clbf = (ConfigurableListableBeanFactory)context.getAutowireCapableBeanFactory();
		// get the main bean definition, there should be only one
		String[] names = clbf.getBeanNamesForType(AuthenticationProvider.class);
		assertEquals(1, names.length);
		RootBeanDefinition definition = (RootBeanDefinition)clbf.getBeanDefinition(names[0]);
	    assertEquals(DaoAuthenticationProvider.class, definition.getBeanClass());
	    
	    
	    // get the 2 inner beans
	    PropertyValue saltSourceBean = definition.getPropertyValues().getPropertyValue("saltSource");
	    assertEquals("saltSource", saltSourceBean.getName());
	    
	    //get the BeanDefinition	    
	    RootBeanDefinition saltsourceDef = (RootBeanDefinition) saltSourceBean.getValue();
	    Assert.isAssignable(SaltSource.class,saltsourceDef.getBeanClass());
	    
	    PropertyValue encoder = definition.getPropertyValues().getPropertyValue("passwordEncoder");
	    assertEquals("passwordEncoder", encoder.getName());
	    
	    //get the BeanDefinition	    
	    RootBeanDefinition encoderDef = (RootBeanDefinition) encoder.getValue();
	    Assert.isAssignable(PasswordEncoder.class,encoderDef.getBeanClass());
	    
		assertEquals("incorrect bean class name", encoderDef.getBeanClassName(),Md5PasswordEncoder.class.getName());
	}
	
	public void testCollaboratorsAsBeanRef() {
		ApplicationContext context = new ClassPathXmlApplicationContext("org/acegisecurity/config/authentication-beanRef-attributes.xml");
		ConfigurableListableBeanFactory clbf = (ConfigurableListableBeanFactory)context.getAutowireCapableBeanFactory();
		//		get the main bean definition, there should be only one
		String[] names = clbf.getBeanNamesForType(AuthenticationProvider.class);
		assertEquals(1, names.length);
		RootBeanDefinition definition = (RootBeanDefinition)clbf.getBeanDefinition(names[0]);
	    assertEquals(DaoAuthenticationProvider.class, definition.getBeanClass());
	    
	    // get the referred collaborators
	    
	    PropertyValue userDetailsBean = definition.getPropertyValues().getPropertyValue("userDetailsService");
	    assertEquals("userDetailsService", userDetailsBean.getName());
	    
	    PropertyValue saltSourceBean = definition.getPropertyValues().getPropertyValue("saltSource");
	    assertEquals("saltSource", saltSourceBean.getName());
	    
	    //get the BeanDefinition	    
	    RuntimeBeanReference saltsourceDef = (RuntimeBeanReference) saltSourceBean.getValue();
	    assertEquals("refToSaltSource",saltsourceDef.getBeanName());
	    
	    PropertyValue encoder = definition.getPropertyValues().getPropertyValue("passwordEncoder");
	    assertEquals("passwordEncoder", encoder.getName());
	    
	    //get the BeanDefinition	    
	    RuntimeBeanReference encoderDef = (RuntimeBeanReference) encoder.getValue();
	    assertEquals("refToPasswordEncoder",encoderDef.getBeanName());
	    
	    DaoAuthenticationProvider provider = (DaoAuthenticationProvider)context.getBean("authenticationRepository");
	    assertTrue(provider.getPasswordEncoder() instanceof PasswordEncoder);
	    assertEquals(Md5PasswordEncoder.class, provider.getPasswordEncoder().getClass() );
	}
	
	public void testAutodetectionOfUserDetailsService(){
		ApplicationContext context = new ClassPathXmlApplicationContext("org/acegisecurity/config/authentication-defaults.xml");
		 DaoAuthenticationProvider provider = (DaoAuthenticationProvider)context.getBean("authenticationRepository");
		 assertNotNull(provider.getUserDetailsService());
		 assertNull(provider.getSaltSource());
		 assertEquals(PlaintextPasswordEncoder.class, provider.getPasswordEncoder().getClass());
		 
	}
}
