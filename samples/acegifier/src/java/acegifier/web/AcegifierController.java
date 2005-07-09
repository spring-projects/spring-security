package acegifier.web;

import org.springframework.web.servlet.mvc.SimpleFormController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.validation.BindException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.beans.BeansException;
import net.sf.acegisecurity.util.InMemoryResource;
import org.w3c.dom.Document;
import org.xml.sax.SAXParseException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.util.HashMap;
import java.util.Map;

import net.sf.acegisecurity.util.WebXmlToAcegiSecurityConverter;

/**
 * Takes a submitted web.xml, applies the transformer to it and returns the resulting
 * modified web.xml and acegi-app-context.xml file contents.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AcegifierController extends SimpleFormController {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

    public AcegifierController() {
        dbf.setValidating(false);
    }

    public ModelAndView onSubmit(
            HttpServletRequest request, HttpServletResponse response, Object command, BindException errors)
                throws Exception {

        AcegifierForm conversion = (AcegifierForm)command;

        ByteArrayInputStream in = new ByteArrayInputStream(conversion.getWebXml().getBytes());
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = null;
        WebXmlToAcegiSecurityConverter converter = null;
        int nBeans = 0;

        try {
            doc = db.parse(in);
            converter = new WebXmlToAcegiSecurityConverter();
            converter.setInput(doc);
            converter.doConversion();
            nBeans = createBeanFactory(converter.getAcegiBeansXml());
        } catch (SAXParseException spe) {
            errors.rejectValue("webXml","parseFailure","Your Web XML Document failed to parse: " + spe.getMessage());
        } catch (BeansException be) {
            errors.rejectValue("webXml","invalidBeans","There was a problem validating the Spring beans: " + be.getMessage());
        }

        if(errors.hasErrors()) {
            return showForm(request, response, errors);
        }

        Map model = new HashMap();
        model.put("webXml", converter.getNewWebXml());
        model.put("acegiBeansXml", converter.getAcegiBeansXml());
        model.put("nBeans", new Integer(nBeans));

        return new ModelAndView("acegificationResults", model);
    }

    /** Creates a BeanFactory from the transformed XML to make sure the results are valid */
    private int createBeanFactory(String beansXml) {
        DefaultListableBeanFactory bf = new DefaultListableBeanFactory();
        XmlBeanDefinitionReader beanReader = new XmlBeanDefinitionReader(bf);

        return beanReader.loadBeanDefinitions(new InMemoryResource(beansXml));
    }

}
