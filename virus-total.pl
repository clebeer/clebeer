#!/usr/bin/perl
# VirusTotal file check
use Switch;
use VT::API;

my $VERSION = "0.01.ALPHA";
    
if (! $ARGV[0]){
print "Usage:\n";
print "\t$0 -r <hash> or -f <file> -V or -h for help.\n\n";
exit(0);
}

# OO-interface.
my $api = VT::API->new(key => 'ADD YOUR VIRUS TOTAL KEY HERE');

switch ($ARGV[0]) {

   case  "-H" {

	if (! $ARGV[1]){
	print "\tVocê precisa indicar um hash para ser analisado.\n";
	exit(0);
	}
	my $res0 = $api->get_file_report($ARGV[1]);

	foreach $key (keys %{$res0}){
		if(ref($res0->{$key}) eq "ARRAY"){
			foreach my $var (@{$res0->{$key}}){
				if (ref($var) eq "HASH"){
					foreach my $var2 (keys %{$var}){
						print "\tANTIVIRUS = $var2 - ".$var->{$var2}."\n";
					}
				}else{
					print "\tTimeStamp = $var\n";
				}
			}
		}elsif (ref($res0->{$key}) eq "HASH"){
			foreach my $var (keys %{$res0->{$key}}){
				print "\tKEY 2=$var\n";
			}
		}else{
			print "Report URL = ".$res0->{$key}."\n";
		}
	}

   }

   case "-f" {

	if (! $ARGV[1]){
        print "\tVocê precisa indicar um arquivo para ser analisado.\n";
        exit(0);
        }

	my $resfile = $api->scan_file($ARGV[1]);

	my $scan_id;

    if ($resfile->{result}) {
        $scan_id = (split(/-/,$resfile->{scan_id}))[0];
    }
    print "scan id = $scan_id\n";

   }  

   case "-U" {

my $res0 = $api->get_url_report($ARGV[1]);

        foreach $key (keys %{$res0}){
                if(ref($res0->{$key}) eq "ARRAY"){
                        foreach my $var (@{$res0->{$key}}){
                                if (ref($var) eq "HASH"){
                                        foreach my $var2 (keys %{$var}){
                                                print "\tBASE = $var2 - ".$var->{$var2}."\n";
                                        }
                                }else{
                                        print "\tTimeStamp = $var\n";
                                }
                        }
                }elsif (ref($res0->{$key}) eq "HASH"){
                        foreach my $var (keys %{$res0->{$key}}){
                                print "\tKEY 2=$var\n";
                        }
                }else{
                        print "URL HASH = ".$res0->{$key}."\n";
                }
        }
}

   case "-A" {
	my $resfile = $api->scan_url($ARGV[0]);

        	my $scan_id;

    	if ($resfile->{result}) {
        	$scan_id = (split(/-/,$resfile->{scan_id}))[0];
    	}	
   	 print "scan id = $scan_id\n";

}

   case "-h" {
	print "\nVirus total file checker ($VERSION)\n Usage:\n\t-H <hash sha256>\t Check hash for report on virus total site.\n ";
	print "\t-U <URL to check>\t Show VirusTotal URL report if exists.\n\t-A <URL to submit>\t Submit an URL to VirusTotal.\n";
	print "\t-f <file to check>\t Submit a file to Virustotal site and returns its hash.\n\t-V\t\t\t Print $0 Version\n\t-h\t\t\t Print this message\n\n";
   }


   case "-V" {
	print "\t $0 - $VERSION\n";
   }

}
