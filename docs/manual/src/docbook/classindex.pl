#! /usr/bin/perl

# Intended to generate an index of classnames to references in the manual (using the interfacename and classname elements).
#
# Builds an index of classnames to Javadoc (or src xref) links, from the allclasses-frame.html file.
# Processes the ref manual docbook files, building an index of classname to section ids where the class is referenced
# 
#
# $Id$

use strict;

# Get list of links to class src packages from Javadoc
#system("curl http://static.springsource.org/spring-security/site/docs/3.0.x/apidocs/allclasses-frame.html > allclasses-frame.html");
# Manual front page gives us section numbers
#system("curl http://static.springsource.org/spring-security/site/docs/3.0.x/reference/springsecurity.html > springsecurity.html");

my $index_page = `cat springsecurity.html`;

my @all_classes = `cat allclasses-frame.html`;

$#all_classes > 0 || die "No lines in Javadoc";

# Src XREF format
#<a href="org/springframework/security/vote/AbstractAccessDecisionManager.html" target="classFrame">AbstractAccessDecisionManager</a>
# Javadoc format
#<A HREF="org/springframework/security/acls/afterinvocation/AbstractAclProvider.html" title="class in org.springframework.security.acls.afterinvocation" target="classFrame">AbstractAclProvider</A>

my %classnames_to_src;

print "Extracting classnames to links map from Javadoc...\n";

while ($_ = pop @all_classes) {
    chomp;
# Get rid of the italic tags round interface names
    $_ =~ s/<I>//;
    $_ =~ s/<\/I>//;    
	next unless $_ =~ /<A HREF="(.*)" title=.*>(([a-zA-Z0-9_]+?))<\/A>.*/;
#	print "Adding class $1, $2\n";
	$classnames_to_src{$2} = $1;
}

#my @docbook = glob("*.xml");
# The list of docbook files xincluded in the manual
my @docbook;

print "Building list of docbook source files...\n";

# Read the includes rather than using globbing to get the ordering right for the index.
open MAINDOC, "<springsecurity.xml";
while(<MAINDOC>) {
	if (/href="(.*\.xml)"/) {
		push @docbook, $1;
	}
}

# Hash of xml:id (i.e. anchor) to filename.html#anchor
my %id_to_html;

# Build map of html pages links
print "Building map of section xml:ids to reference manual links...\n";
while (my $file = pop @docbook) {
	open FILE, $file or die "$!";	
#	print "\nProcessing: $file\n\n";
	my $file_id;
	while(<FILE>) {
		if (/.* xml:id="([a-z0-9-]+?)"/) {
			$file_id = $1;
			last;
		}
	}

	$id_to_html{$file_id} = "$file_id.html";
 
	while (<FILE>) {
		next unless /.* xml:id="([a-z0-9-]+?)"/;
#		print "$1\n";
		$id_to_html{$1} = "$file_id.html#$1";
	}
	close FILE;
}

# Get the list of class/interface names and their section ids/titles
print "Obtaining class and interface references from manual...\n";
my @class_references = split /;/,`xsltproc --xinclude index-classes.xsl springsecurity.xml`;
# Get unique values
my %seen = ();
@class_references = grep { !$seen{$_}++} @class_references;
print "There are $#class_references references to classes and interfaces.\n";

my %id_to_title;
my %classnames_to_ids = ();

foreach my $class_id_title (@class_references) {
	(my $class, my $id, my $title) = split /:/, $class_id_title;
	$title =~ s/</&lt;/;
	$title =~ s/>/&gt;/;
	$id_to_title{$id} = $title;
	push( @{$classnames_to_ids{$class}}, $id );
}

print "Writing index file...\n";
open INDEX, ">classindex.xml" || die "Couldn't open output file\n";
print INDEX "<index>\n";
foreach my $class (sort keys %classnames_to_ids) {
	print INDEX "<class name='$class'"; 
	if (exists $classnames_to_src{$class}) {
		print INDEX " src-xref='$classnames_to_src{$class}'";
	}
	print INDEX ">\n";
	foreach my $id (@{$classnames_to_ids{$class}}) {
	    my $href = $id_to_html{$id};
	    $index_page =~ /$href">([AB0-9\.]* )/;
	    my $section = $1 ? "$1" : "";
#	    print "$id $href $section\n";
	    my $title = $id_to_title{$id};
#	    print "$section$title\n";
		print INDEX "    <link href='$href' title='$section$title'/>\n";
	}
	print INDEX "</class>\n"
	
}
print INDEX "</index>\n";
close INDEX;

print "Generating HTML file...\n"; 

system("xsltproc class-index-html.xsl classindex.xml > class-index.html");
