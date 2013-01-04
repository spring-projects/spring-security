package trang;

import com.thaiopensource.relaxng.translate.Driver

import javax.xml.transform.Transformer
import javax.xml.transform.TransformerFactory
import javax.xml.transform.stream.StreamSource
import javax.xml.transform.stream.StreamResult

import org.gradle.api.*;
import org.gradle.api.tasks.*
import org.gradle.api.file.FileCollection

/**
 * Used for converting .rnc files to .xsd files.
 * @author Rob Winch
 */
class TrangPlugin implements Plugin<Project> {
    public void apply(Project project) {
        Task rncToXsd = project.tasks.add('rncToXsd', RncToXsd.class)
        rncToXsd.description = 'Converts .rnc to .xsd'
        rncToXsd.group = 'Build'
    }
}

/**
 * Converts .rnc files to .xsd files using trang and then applies an xsl file to cleanup the results.
 */
public class RncToXsd extends DefaultTask {
    @InputDirectory
    File rncDir

    @InputFile
    File xslFile

    @OutputDirectory
    File xsdDir

    @TaskAction
    public final void transform() {
        String xslPath = xslFile.absolutePath
        rncDir.listFiles( { dir, file -> file.endsWith('.rnc')} as FilenameFilter).each { rncFile ->
            File xsdFile = new File(xsdDir, rncFile.name.replace('.rnc', '.xsd'))
            String xsdOutputPath = xsdFile.absolutePath
            new Driver().run([rncFile.absolutePath, xsdOutputPath] as String[]);

            TransformerFactory tFactory = new net.sf.saxon.TransformerFactoryImpl()
            Transformer transformer =
                    tFactory.newTransformer(new StreamSource(xslPath))
            File temp = File.createTempFile("gradle-trang-" + xsdFile.name, ".xsd")
            xsdFile.withInputStream { is ->
                temp << is
            }
            StreamSource xmlSource = new StreamSource(temp)
            transformer.transform(xmlSource, new StreamResult(xsdFile))
            temp.delete()
        }
    }
}