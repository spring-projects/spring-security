<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<html>
<head>
<title>Acegi Security Web.xml Converter</title>
</head>
<body>

<p>Congratulations! Your web.xml file has been "Acegified" successfully.</p>

<h2>Web.xml</h2>
<p>
This is the converted web.xml file which you should use in your Acegi-Secured
Spring application. It should contain the mechanism for loading the Spring application
context file which defines your security configuration as well as the
necessary filters to apply this configuration.
</p>

<pre>
${webXml?xml}
</pre>

<h2>Acegi Security Beans</h2>
<p>
This is the file which defines your security configuration (a standard Spring
application context file). It should be named "applicationContext-acegi-security.xml"
and placed in your WEB-INF directory.
</p>

<pre>
${acegiBeansXml?xml}
</pre>

<p>Note that these files may require some manual changes before they work as expected and are
intended as a guide only :).</p>


</body>
</html>