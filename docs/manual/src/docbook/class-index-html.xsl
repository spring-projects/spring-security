<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <!-- Run with xsltproc class-index-html.xsl classindex.xml > class-index.html -->    
    
  <xsl:variable name="src-xref-base">http://static.springsource.org/spring-security/site/docs/3.0.x/apidocs/</xsl:variable>
  <xsl:variable name="ref-man-base">http://static.springsource.org/spring-security/site/docs/3.0.x/reference/</xsl:variable>  

  <xsl:template match="index">
    <html>
      <head>
        <title>Spring Security Class and Interface Index</title>
      </head>
      <body>
        <h2>Class and Interface Index</h2>
        <p>An list of classes and interfaces used in Spring Security with links to the sections in the Spring Security manual which 
        refer to them.</p>
        <div id="classindex">
        <xsl:apply-templates />
        </div>
      </body>
    </html>  
  </xsl:template>

  <xsl:template match="class">
    <div class="index-class">
    <xsl:choose>
      <xsl:when test="@src-xref">
      <h4><xsl:element name="a"><xsl:attribute name="href"><xsl:value-of select="concat($src-xref-base, @src-xref)"/></xsl:attribute><xsl:value-of select="@name"/></xsl:element></h4>
      </xsl:when>
      <xsl:otherwise>
        <h4><span class="classname"><xsl:value-of select="@name"/></span></h4>      
      </xsl:otherwise>
    </xsl:choose>
    <table>
    <xsl:for-each select="link">
      <tr><td><xsl:element name="a"><xsl:attribute name="href"><xsl:value-of select="concat($ref-man-base, @href)"/></xsl:attribute><xsl:value-of select="@title"/></xsl:element></td>
      </tr>
    </xsl:for-each>
    </table>  
    </div>
  </xsl:template>

</xsl:stylesheet>
