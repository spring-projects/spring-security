package net.sf.acegisecurity.util;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.DOMImplementation;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.xml.sax.SAXException;

import javax.xml.transform.stream.StreamSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.Source;
import javax.xml.transform.Result;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.dom.DOMResult;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.FileOutputStream;
import java.io.InputStream;


/**
 * A utility to translate a web.xml file into a set of
 * acegi security spring beans.
 *
 * <p>
 * This class wraps the XSL transform which actually does
 * most of the work. It also tests the result by
 * loading it into a Spring bean factory.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class WebXmlSecurityToSpringBeansTranslator {
    private String webToSpringXsltFile = "web-to-spring.xsl";
    private String outputFileName = "applicationContext-acegi-security.xml";
    private Transformer transformer, identityTransformer;
    private DefaultListableBeanFactory beanFactory;
    DocumentBuilderFactory dbf;

    public WebXmlSecurityToSpringBeansTranslator() throws Exception {
        ClassPathResource resource = new ClassPathResource(webToSpringXsltFile);
        Source xsltSource = new StreamSource(resource.getInputStream());
        dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        TransformerFactory tf = TransformerFactory.newInstance();
        transformer = tf.newTransformer(xsltSource);
        identityTransformer = tf.newTransformer();
        identityTransformer.setOutputProperty(OutputKeys.DOCTYPE_PUBLIC, "-//SPRING//DTD BEAN//EN");
        identityTransformer.setOutputProperty(OutputKeys.DOCTYPE_SYSTEM, "http://www.springframework.org/dtd/spring-beans.dtd");
    }

    public void translate(InputStream in) throws TransformerException, IOException, ParserConfigurationException, SAXException {
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document d = db.parse(in);
        translate(d);
    }

    /**
     * Converts the web.xml supplied as a DOM Node
     *
     * @param webXml the web application xml
     */
    public void translate(Node webXml) throws IOException, TransformerException, ParserConfigurationException {
        Source xmlSource = new DOMSource(webXml);
        DOMResult domResult = new DOMResult();

        transformer.transform(xmlSource, domResult);

        // Obtain DOM for additional manipulation here.
        Node document = domResult.getNode();

        // Tranform DOM with identity transform to get the output file
        Result streamResult = new StreamResult(new FileOutputStream(outputFileName));
        xmlSource = new DOMSource(document);
        identityTransformer.transform(xmlSource, streamResult);
        beanFactory = new DefaultListableBeanFactory();
        XmlBeanDefinitionReader beanReader = new XmlBeanDefinitionReader(beanFactory);
        beanReader.loadBeanDefinitions(new FileSystemResource(outputFileName));
    }

    public String getOutputFileName() {
        return outputFileName;
    }

    public void setOutputFileName(String outputFileName) {
        this.outputFileName = outputFileName;
    }

    /**
     * Mainly intended for testing
     * @return the bean factory built from the created acegi security application context file
     *
     */
    public BeanFactory getBeanFactory() {
        return beanFactory;
    }
}
