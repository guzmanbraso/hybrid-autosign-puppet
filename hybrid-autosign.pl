#!/usr/bin/perl
#
# Hybrid Autosign
#
# This script will check CSR received by puppetmaster and sign based on
# valid preshared keys or IP address of the agent that requested
#
use strict;
use warnings;
use Data::Dumper;
use YAML::Tiny;
use NetAddr::IP;
use POSIX;

# Open config
my $yaml = YAML::Tiny->read( '/etc/puppet/hybrid-autosign-puppet/hybrid-autosign.yaml' );

# Subroutine to log actions
sub execlog($) {
  my $msg = shift;
  my $return = shift;
  my $scriptlog = $yaml->[0]->{':config'}->[1]->{'scriptlog'};
  open(my $fh, '>>', $scriptlog) or die "Could not open file '$scriptlog' $!";
  my $now = POSIX::strftime("%m/%d/%Y %H:%M:%S\n", localtime);
  chomp($now);
  print $fh "$now - $msg\n";
  close $fh;
}

# Read certname and CSR        
my $certname=$ARGV[0];
my $csr = do { local $/; <STDIN> };

# Parse accesslog and get the IP & environment this request was submitted to 
my $accesslog = $yaml->[0]->{':config'}->[0]->{'accesslog'};
my $req_ip;
my $req_env;
open my $FH, '<', $accesslog or die "could not open '$accesslog', because the OS said: $!";
while ( <$FH> ) {
  if ( m/(\d+\.\d+\.\d+\.\d+) .*GET \/(\w+)\/certificate_request\/$certname/ ) {
    $req_ip = $1;
    $req_env = $2;
  }
}

# Check if IP is allowed
my $ip = NetAddr::IP->new($req_ip);
foreach my $network_block (@{$yaml->[0]->{':networks_allowed'}}) {
  my $network = NetAddr::IP->new($network_block);
  if ($ip->within($network)) {
    execlog("Signed CSR $certname because is on network whitelist - IP $req_ip - Env: $req_env");
    exit 0;
  }
}

# check if a shared key is comming
my $req_shared_key;
$req_shared_key=`echo "$csr" |openssl req -noout -text|grep -A1 1.3.6.1.4.1.34380.1.1.4|tail -n 1`;
if ($req_shared_key) {
  $req_shared_key =~ s/^\s+|\s+$//g;
  my $keys_folder=$yaml->[0]->{':config'}->[2]->{'keys_folder'};
  my @valid_keys = <${keys_folder}*>;
  foreach my $valid_key (@valid_keys) {
    open(KEY, $valid_key) or die "Can't read file '$valid_key' [$!]\n";  
    my $key = <KEY>; 
    close (KEY);
    if ($key eq $req_shared_key) {
      (my $keyname = $valid_key) =~s/.*\///;
      execlog("Signed CSR $certname because have a valid key - IP $req_ip - Env: $req_env - Key name: $keyname");
      exit 0;
    }
  }
} else {
  $req_shared_key='N/A';
}

execlog("Refused to sign CSR from $certname - IP: $req_ip - Env: $req_env - Incomming key: $req_shared_key");
exit 1;

