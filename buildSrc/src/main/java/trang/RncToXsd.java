package trang;

import com.thaiopensource.relaxng.translate.Driver;
import net.sf.saxon.TransformerFactoryImpl;
import org.gradle.api.DefaultTask;
import org.gradle.api.tasks.InputDirectory;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.OutputDirectory;
import org.gradle.api.tasks.TaskAction;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/**
 * Converts .rnc files to .xsd files using trang and then applies an xsl file to cleanup the results.
 */
public class RncToXsd extends DefaultTask {

	private File rncDir;

	private File xslFile;

	private File xsdDir;

	@InputDirectory
	public File getRncDir() {
		return rncDir;
	}

	public void setRncDir(File rncDir) {
		this.rncDir = rncDir;
	}

	@InputFile
	public File getXslFile() {
		return xslFile;
	}

	public void setXslFile(File xslFile) {
		this.xslFile = xslFile;
	}

	@OutputDirectory
	public File getXsdDir() {
		return xsdDir;
	}

	public void setXsdDir(File xsdDir) {
		this.xsdDir = xsdDir;
	}

	@TaskAction
	public final void transform() throws IOException, TransformerException {
		String xslPath = xslFile.getAbsolutePath();

		File[] files = rncDir.listFiles((dir, file) -> file.endsWith(".rnc"));
		if(files != null) {
			for (File rncFile : files) {
				File xsdFile = new File(xsdDir, rncFile.getName().replace(".rnc", ".xsd"));
				String xsdOutputPath = xsdFile.getAbsolutePath();

				new Driver().run(new String[]{rncFile.getAbsolutePath(), xsdOutputPath});

				TransformerFactory tFactory = new TransformerFactoryImpl();
				Transformer transformer = tFactory.newTransformer(new StreamSource(xslPath));

				File temp = File.createTempFile("gradle-trang-" + xsdFile.getName(), ".xsd");

				Files.copy(xsdFile.toPath(), temp.toPath(), StandardCopyOption.REPLACE_EXISTING);
				StreamSource xmlSource = new StreamSource(temp);
				transformer.transform(xmlSource, new StreamResult(xsdFile));
				temp.delete();
			}
		}
	}
}
