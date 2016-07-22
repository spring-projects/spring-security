package org.springframework.security.config

import groovy.xml.MarkupBuilder
import org.mockito.Mockito
import org.springframework.context.ApplicationListener
import org.springframework.context.support.AbstractRefreshableApplicationContext
import org.springframework.mock.web.MockServletContext
import org.springframework.security.CollectingAppListener
import org.springframework.security.config.util.InMemoryXmlApplicationContext
import org.springframework.security.config.util.InMemoryXmlWebApplicationContext
import org.springframework.security.core.context.SecurityContextHolder
import spock.lang.Specification

import javax.servlet.ServletContext

import static org.springframework.security.config.ConfigTestUtils.AUTH_PROVIDER_XML
/**
 *
 * @author Luke Taylor
 */
abstract class AbstractXmlConfigTests extends Specification {
	AbstractRefreshableApplicationContext appContext;
	Writer writer;
	MarkupBuilder xml;
	ApplicationListener appListener;

	def setup() {
		writer = new StringWriter()
		xml = new MarkupBuilder(writer)
		appListener = new CollectingAppListener()
	}

	def cleanup() {
		if (appContext != null) {
			appContext.close();
			appContext = null;
		}
		SecurityContextHolder.clearContext();
	}

	def mockBean(Class clazz, String id = clazz.simpleName) {
		xml.'b:bean'(id: id, 'class': Mockito.class.name, 'factory-method':'mock') {
			'b:constructor-arg'(value : clazz.name)
			'b:constructor-arg'(value : id)
		}
	}

	def bean(String name, Class clazz) {
		xml.'b:bean'(id: name, 'class': clazz.name)
	}

	def bean(String name, String clazz) {
		xml.'b:bean'(id: name, 'class': clazz)
	}

	def bean(String name, String clazz, List constructorArgs) {
		xml.'b:bean'(id: name, 'class': clazz) {
			constructorArgs.each { val ->
				'b:constructor-arg'(value: val)
			}
		}
	}

	def bean(String name, String clazz, Map properties, Map refs) {
		xml.'b:bean'(id: name, 'class': clazz) {
			properties.each {key, val ->
				'b:property'(name: key, value: val)
			}
			refs.each {key, val ->
				'b:property'(name: key, ref: val)
			}
		}
	}

	def createAppContext() {
		createAppContext(AUTH_PROVIDER_XML)
	}

	def createAppContext(String extraXml) {
		appContext = new InMemoryXmlApplicationContext(writer.toString() + extraXml);
		appContext.addApplicationListener(appListener);
	}

	def createWebAppContext() {
		createWebAppContext(AUTH_PROVIDER_XML);
	}

	def createWebAppContext(ServletContext servletContext) {
		createWebAppContext(AUTH_PROVIDER_XML, servletContext);
	}

	def createWebAppContext(String extraXml) {
		createWebAppContext(extraXml, null);
	}

	def createWebAppContext(String extraXml, ServletContext servletContext) {
		appContext = new InMemoryXmlWebApplicationContext(writer.toString() + extraXml);
		appContext.addApplicationListener(appListener);
		if (servletContext != null) {
			appContext.setServletContext(servletContext);
		} else {
			appContext.setServletContext(new MockServletContext());
		}
		appContext.refresh();
	}
}
