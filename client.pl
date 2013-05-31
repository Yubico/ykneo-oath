#!/usr/bin/perl

# Copyright (c) 2013 Yubico AB
# All rights reserved.

use strict;
use warnings;

use Chipcard::PCSC;
use Getopt::Long;

my $readerMatch;
my $action;
my $name;
my $key;
my $challenge;
my $type = 1;
my $code;
my $debug;
my $digits = 6;

GetOptions("reader=s" => \$readerMatch,
           "list" => \&set_action,
           "put" => \&set_action,
           "delete" => \&set_action,
           "name=s" => \$name,
           "key=s" => \$key,
           "calculate" => \&set_action,
           "challenge=s" => \$challenge,
           "type=i" => \$type,
           "code=s" => \$code,
           "change-code" => \&set_action,
           "debug" => \$debug,
           "digits=i" => \$digits);

my $reader;

my $rContext = new Chipcard::PCSC;
my @readers = $rContext->ListReaders();
foreach my $read (@readers) {
  if(defined($readerMatch)) {
    next unless $read =~ m/.*$readerMatch.*/;
  }
  print "Using reader $read\n" if $debug;
  $reader = $read;
  last;
}
die "No reader found." unless $reader;

my $card = new Chipcard::PCSC::Card($rContext, $reader, $Chipcard::PCSC::SCARD_SHARE_SHARED);
die "Card connection failed." unless $card;

# select applet
$card->TransmitWithCheck("00 a4 04 00 07 a0 00 00 05 27 21 01", "90 00", $debug);

if(defined($code)) {
  my $code_p = unpack_hex($code);
  my $len = scalar(@$code_p) + 2;
  my @apdu = (0x00, 0xa3, 0x00, 0x00, $len, 0x7e, scalar(@$code_p), @$code_p);
  my $repl = send_apdu(\@apdu);
  if($repl->[0] != 0x90) {
    die "wrong code, " . $repl->[1] . " attempts left.";
  }
}

die "no action specified" unless $action;

if($action eq 'change-code') {
  die "No key specified." unless $key;
  my $key_p = unpack_hex($key);
  my $len = scalar(@$key_p) + 2;
  my @apdu = (0x00, 0x03, 0x00, 0x00, $len, 0x7e, scalar(@$key_p), @$key_p);
  my $repl = send_apdu(\@apdu);
  if($repl->[0] != 0x90) {
    die "failed setting code.";
  }
}

if($action eq 'list') {
  my $repl = send_apdu([0x00, 0xa1, 0x00, 0x00]);
  if($repl->[0] != 0xa1) {
    die "unknown reply: " . $repl->[0];
  }
  my $offs = 1;
  my $len = get_len($repl, $offs);
  $offs += get_len_bytes($len);
  while($offs < ($len)) {
    print $repl->[$offs++] . " : ";
    my $length = get_len($repl, $offs++);
    for(my $i = 0; $i < $length; $i++) {
      print chr($repl->[$offs + $i]);
    }
    print "\n";
    $offs += $length;
  }
}

if($action eq 'put') {
  die "No name specified." unless $name;
  die "No key specified." unless $key;

  my @name_p = unpack("C*", $name);
  my $key_p = unpack_hex($key);
  my $len = scalar(@name_p) + 2 + scalar(@$key_p) + 3;
  my @apdu = (0x00, 0x01, 0x00, 0x00, $len, 0x7a, scalar(@name_p), @name_p, 0x7b, $type, scalar(@$key_p), @$key_p);
  my $repl = send_apdu(\@apdu);
}

if($action eq 'delete') {
  die "No name specified." unless $name;
  my @name_p = unpack("C*", $name);
  my $len = scalar(@name_p) + 2;
  my @apdu = (0x00, 0x02, 0x00, 0x00, $len, 0x7a, scalar(@name_p), @name_p);
  my $repl = send_apdu(\@apdu);
}

if($action eq 'calculate') {
  die "No name specified." unless $name;
  die "No challenge specified." unless $challenge;

  my @name_p = unpack("C*", $name);
  my $chal_p = unpack_hex($challenge);
  my $len = scalar(@name_p) + 2 + scalar(@$chal_p) + 2;
  my @apdu = (0x00, 0xa2, 0x00, 0x00, $len, 0x7a, scalar(@name_p), @name_p, 0x7d, scalar(@$chal_p), @$chal_p);
  my $repl = send_apdu(\@apdu);

  die "error on calc" unless $repl->[0] == 0x7d;
  my $offs = $repl->[scalar(@$repl) - 3] & 0xf;
  $offs += 2; # status and length..
  my $code = (($repl->[$offs++] & 0x7f) << 24) |
    (($repl->[$offs++] & 0xff) << 16) |
    (($repl->[$offs++] & 0xff) << 8) |
    ($repl->[$offs++] & 0xff);
  printf("code is %0${digits}d\n", $code % (10 ** $digits));
}

sub get_len {
  my ($buf, $offs) = @_;
  if($buf->[$offs] < 0x80) {
    return $buf->[$offs];
  } elsif($buf->[$offs] == 0x81) {
    return $buf->[$offs + 1];
  } elsif($buf->[$offs] == 0x82) {
    return ($buf->[$offs + 1] << 8) + $buf->[$offs + 2];
  }
}

sub get_len_bytes {
  my $len = shift;
  if($len < 0x80) {
    return 1;
  } elsif($len <= 0xff) {
    return 2;
  } else {
    return 3;
  }
}

sub set_action {
  my ($opt_name, $opt_value) = @_;
  $action = $opt_name;
}

sub unpack_hex {
  my $input = shift;
  my $hex;
  if($input =~ m/^([0-9a-fA-F]{2}\s)+$/) {
    $hex = Chipcard::PCSC::ascii_to_array($input);
  } else {
    my @hex_tmp = unpack("C*", $input);
    $hex = \@hex_tmp;
  }
  return $hex;
}

sub send_apdu {
  my $apdu = shift;
  if($debug) {
    print "=> ";
    foreach my $tmp (@$apdu) {
      printf ("%02x ", $tmp);
    } print "\n";
  }
  my $repl = $card->Transmit($apdu);
  if($debug) {
    print "<= ";
    foreach my $tmpVal (@{$repl}) {
      printf ("%02x ", $tmpVal);
    } print "\n";
  }
  return $repl;
}
