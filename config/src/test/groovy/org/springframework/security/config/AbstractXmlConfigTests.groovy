package org.springframework.security.config

import static org.springframework.security.config.ConfigTestUtils.AUTH_PROVIDER_XML;

import groovy.xml.MarkupBuilder
import java.util.List;
import java.util.Map;

import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.config.util.InMemoryXmlApplicationContext
import org.springframework.security.core.context.SecurityContextHolder

import spock.lang.Specification

/**
 *
 * @author Luke Taylor
 */
abstract class AbstractXmlConfigTests extends Specification {
    AbstractXmlApplicationContext appContext;
    Writer writer;
    MarkupBuilder xml;

    def setup() {
        writer = new StringWriter()
        xml = new MarkupBuilder(writer)
    }

    def cleanup() {
        if (appContext != null) {
            appContext.close();
            appContext = null;
        }
        SecurityContextHolder.clearContext();
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
    }
}
