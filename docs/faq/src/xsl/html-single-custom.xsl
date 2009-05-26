<?xml version="1.0" encoding="UTF-8"?>

<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
				xmlns:xslthl="http://xslthl.sf.net"
				exclude-result-prefixes="xslthl"
				version='1.0'>

    <xsl:import href="http://docbook.sourceforge.net/release/xsl/current/html/docbook.xsl"/>	
	<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/html/highlight.xsl"/>
	
	<!--xsl:param name="use.id.as.filename">'1'</xsl:param-->

	<!-- Use code syntax highlighting -->
	<xsl:param name="highlight.source">1</xsl:param>

<!-- Extensions 
	<xsl:param name="use.extensions">1</xsl:param>
	<xsl:param name="tablecolumns.extension">0</xsl:param>
	<xsl:param name="callout.extensions">1</xsl:param>
-->
<!-- Activate Graphics 
	<xsl:param name="admon.graphics" select="1"/>
	<xsl:param name="admon.graphics.path">images/</xsl:param>
	<xsl:param name="admon.graphics.extension">.gif</xsl:param>
	<xsl:param name="callout.graphics" select="1" />
	<xsl:param name="callout.defaultcolumn">120</xsl:param>
	<xsl:param name="callout.graphics.path">images/callouts/</xsl:param>
	<xsl:param name="callout.graphics.extension">.gif</xsl:param>
-->	
	<xsl:param name="table.borders.with.css" select="1"/>
	<xsl:param name="html.stylesheet">css/faq.css</xsl:param>
	<xsl:param name="html.stylesheet.type">text/css</xsl:param>

	<!--xsl:param name="generate.toc">book toc,title</xsl:param-->
<!--
	<xsl:param name="admonition.title.properties">text-align: left</xsl:param>

	<xsl:param name="section.label.includes.component.label" select="1"/>
	<xsl:param name="table.footnote.number.format" select="'1'"/>
-->
	<xsl:template match='xslthl:keyword' mode="xslthl">
		<span class="hl-keyword"><xsl:apply-templates mode="xslthl"/></span>
	</xsl:template>

	<xsl:template match='xslthl:comment' mode="xslthl">
		<span class="hl-comment"><xsl:apply-templates mode="xslthl"/></span>
	</xsl:template>

	<xsl:template match='xslthl:oneline-comment' mode="xslthl">
		<span class="hl-comment"><xsl:apply-templates mode="xslthl"/></span>
	</xsl:template>

	<xsl:template match='xslthl:multiline-comment' mode="xslthl">
		<span class="hl-multiline-comment"><xsl:apply-templates mode="xslthl"/></span>
	</xsl:template>

	<xsl:template match='xslthl:tag' mode="xslthl">
		<span class="hl-tag"><xsl:apply-templates mode="xslthl"/></span>
	</xsl:template>

	<xsl:template match='xslthl:attribute' mode="xslthl">
		<span class="hl-attribute"><xsl:apply-templates mode="xslthl"/></span>
	</xsl:template>

	<xsl:template match='xslthl:value' mode="xslthl">
		<span class="hl-value"><xsl:apply-templates mode="xslthl"/></span>
	</xsl:template>
	
	<xsl:template match='xslthl:string' mode="xslthl">
		<span class="hl-string"><xsl:apply-templates mode="xslthl"/></span>
	</xsl:template>

	<!-- Google Analytics -->
	<xsl:template name="user.head.content">
		<xsl:comment>Begin Google Analytics code</xsl:comment>
		<script type="text/javascript">
			var gaJsHost = (("https:" == document.location.protocol) ? "https://ssl." : "http://www.");
			document.write(unescape("%3Cscript src='" + gaJsHost + "google-analytics.com/ga.js' type='text/javascript'%3E%3C/script%3E"));
		</script>
		<script type="text/javascript">
			var pageTracker = _gat._getTracker("UA-2728886-3");
			pageTracker._setDomainName("none");
			pageTracker._setAllowLinker(true);
			pageTracker._trackPageview();
		</script>
		<xsl:comment>End Google Analytics code</xsl:comment>
	</xsl:template>

	<!-- Loopfuse -->
	<xsl:template name="user.footer.content">
		<xsl:comment>Begin LoopFuse code</xsl:comment>
		<script src="http://loopfuse.net/webrecorder/js/listen.js" type="text/javascript">
		</script>
		<script type="text/javascript">
			_lf_cid = "LF_48be82fa";
			_lf_remora();
		</script>
		<xsl:comment>End LoopFuse code</xsl:comment>
	</xsl:template>

</xsl:stylesheet>