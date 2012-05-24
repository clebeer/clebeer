#!/usr/bin/perl
use Switch;
use Shodan::WebAPI;

my $VERSION = "0.01.ALPHA";

$SHODAN_API_KEY = "ADD YOUR SHODAN KEY HERE";
$api = new Shodan::WebAPI($SHODAN_API_KEY);


	if (! $ARGV[0]){
		print "Usage:\n";
		print "\t$0 -s <search> or -h <host> or -V for version number.\n\n";
		exit(0);
	}


switch ($ARGV[0]) {

	case "-s" {
		&shodan_search()
	}
	
	case "-h" {
		&shodan_host()
	}
	
	case "-V" {
		print "$VERSION\n";
	}
}


sub shodan_search() {

	$results = $api->search($ARGV[1]);

	if ( $result->{'error'} ) {
        	print "Error: " . $result->{'error'} . "\n";
	}
	else {
        	@matches = @{$results->{'matches'}};
	        for ( $i = 0; $i < $#matches; $i++ ) {
        	        print "IP: $matches[$i]->{ip}\n";
        	        print "DATA: $matches[$i]->{data}\n";
        	}	
	}

}

sub shodan_host() {
	my $IP = "$ARGV[1]";

	$host = $api->host($IP);

	if ( $host->{'error'} ) {
        	print "Error: " . $host->{'error'} . "\n";
	}
	else {
		print "IP: $host['ip']\n";
		print "DATA: $host['data']\n";
	}

}

sub shodan_xpl() {

	$xpl = $api->exploitdb_search($ARGV[1]);

	print "Results found: $xpl->{total}\n";
	@matches = @{ $xpl->{matches} };
	for ( $i = 0; $i < $#matches; $i++ ) {
        	print "$matches[$i]{id}: $matches[$i]{description}\n";
	}
}
