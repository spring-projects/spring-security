#! /usr/bin/perl

use strict;

# Get list of links to class src packages
system("curl http://static.springframework.org/spring-security/site/xref/allclasses-frame.html > allclasses-frame.html");
my @all_classes = `cat allclasses-frame.html`;

$#all_classes > 0 || die "No lines in xref";

#<a href="org/springframework/security/vote/AbstractAccessDecisionManager.html" target="classFrame">AbstractAccessDecisionManager</a>

my %classnames_to_src;

while ($_ = pop @all_classes) {
	next unless $_ =~ /<a href="(.*)" target="classFrame">(([a-zA-Z0-9_]+?))<\/a>/;
	$classnames_to_src{$2} = $1;
}

#my @docbook = glob("*.xml");
my @docbook;

# Read the includes rather than using globbing to get the ordering right for the index.
open MAINDOC, "<springsecurity.xml";
while(<MAINDOC>) {
	if (/href="(.*\.xml)"/) {
		push @docbook, $1;
	}
}

# Hash of xml:id (i.e. anchor) to filename.html#anchor
my %id_to_html;
my %class_index;

# Build map of html pages links
while (my $file = pop @docbook) {
	open FILE, $file or die "$!";	
	print "\nProcessing: $file\n\n";
	my $file_id;
	while(<FILE>) {
		if (/.* xml:id="([a-z0-9-]+?)"/) {
			$file_id = $1;
			last;
		}
	}

	$id_to_html{$file_id} = "$file_id.html#$file_id";
 
	while (<FILE>) {
		next unless /.* xml:id="([a-z0-9-]+?)"/;
		print "$1\n";
		$id_to_html{$1} = "$file_id.html#$1";
	}
	close FILE;
}

# Get the list of class/interface names and their section ids/titles
my @class_references = split /;/,`xsltproc --xinclude index-classes.xsl springsecurity.xml`;
# Get unique values
my %seen = ();
@class_references = grep { !$seen{$_}++} @class_references;
print "\nThere are $#class_references references to classes and interfaces.\n";

my %id_to_title;
my %classnames_to_ids = ();

foreach my $class_id_title (@class_references) {
	(my $class, my $id, my $title) = split /:/, $class_id_title;
	$title =~ s/</&lt;/;
	$title =~ s/>/&gt;/;
	$id_to_title{$id} = $title;
	push( @{$classnames_to_ids{$class}}, $id );
}
open INDEX, ">classindex.xml" || die "Couldn't open output file\n";
print INDEX "<index>\n";
foreach my $class (sort keys %classnames_to_ids) {
	print INDEX "<class name='$class'"; 
	if (exists $classnames_to_src{$class}) {
		print INDEX " src-xref='$classnames_to_src{$class}'";
	}
	print INDEX ">\n";
	foreach my $id (@{$classnames_to_ids{$class}}) {
		print INDEX "    <link href='$id_to_html{$id}' title='$id_to_title{$id}'/>\n";
	}
	print INDEX "</class>\n"
	
	
}
print INDEX "</index>\n";
close INDEX;
