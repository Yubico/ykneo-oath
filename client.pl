#!/usr/bin/perl

# Copyright (c) 2013 Yubico AB
# All rights reserved.

use strict;
use warnings;

use Chipcard::PCSC;
use Getopt::Long;
use Pod::Usage;
use Digest::SHA qw(hmac_sha1 hmac_sha256);

my $challenge_length = 8;

my $readerMatch;
my $action;
my $name;
my $key;
my $challenge;
my $type = 1;
my $code;
my $debug;
my $digits = 6;
my $help = 0;

my $name_tag = 0x71;
my $name_list_tag = 0x72;
my $key_tag = 0x73;
my $challenge_tag = 0x74;
my $response_tag = 0x75;
my $t_response_tag = 0x76;
my $no_response_tag = 0x77;
my $property_tag = 0x78;

GetOptions("reader=s" => \$readerMatch,
           "list" => \&set_action,
           "put" => \&set_action,
           "delete" => \&set_action,
           "name=s" => \$name,
           "key=s" => \$key,
           "calculate" => \&set_action,
           "calculate-all" => \&set_action,
           "challenge=s" => \$challenge,
           "type=i" => \$type,
           "code=s" => \$code,
           "change-code" => \&set_action,
           "debug" => \$debug,
           "digits=i" => \$digits,
           "help" => \$help);

pod2usage(1) if $help;

my $reader;

my $rContext = new Chipcard::PCSC;
my @readers = $rContext->ListReaders();
foreach my $read (@readers) {
  if(defined($readerMatch)) {
    next unless $read =~ m/.*$readerMatch.*/;
  }
  $reader = $read;
  last;
}
die "No reader found." unless $reader;
print "Using reader $reader\n" if $debug;

my $card = new Chipcard::PCSC::Card($rContext, $reader, $Chipcard::PCSC::SCARD_SHARE_SHARED);
die "Card connection failed." unless $card;

# select applet
my $sw = $card->TransmitWithCheck("00 a4 04 00 07 a0 00 00 05 27 21 01", "90 00", $debug);
die "Failed to select applet." unless defined $sw;

if(defined($code)) {
  my $code_p = unpack_hex($code);
  my $challenge;
  for(my $i = 0; $i < $challenge_length; $i++) {
    $challenge .= sprintf("%02x ", rand(0xff));
  }
  my $chal_p = unpack_hex($challenge);
  my $len = scalar(@$chal_p) + 2;
  my @apdu = (0x00, 0xa3, 0x00, 0x00, $len, $challenge_tag, $challenge_length, @$chal_p);
  my $repl = send_apdu(\@apdu);
  if($repl->[0] != 0x7e) {
    die "wrong answer from server.." . $repl->[0];
  }
  my $length = $repl->[3];
  my $hash_func;
  if($length == 20) {
    $hash_func = \&hmac_sha1;
  } elsif($length == 32) {
    $hash_func = \&hmac_sha256;
  } else {
    die "unknown length: $length";
  }
  my @answer;
  for(my $i = 4; $i < $length + 4; $i++) {
    push(@answer, $repl->[$i]);
  }
  my $answer_pack = pack('C' . $length, @answer);
  my $code_pack = pack('C' . scalar(@$code_p), @$code_p);
  my $chal_pack = pack('C' . $challenge_length, @$chal_p);
  my $correct = &$hash_func($chal_pack, $code_pack);
  if($correct ne $answer_pack) {
    die "answer does not match expected!";
  }
  if($repl->[$length + 4] != 0x7f) {
    die "unexpected tag: " . $repl->[$length + 4];
  }
  my $offs = $length + 6;
  $length = $repl->[$length + 5];
  my $new_chal;
  for(my $i = $offs; $i < $length + $offs; $i++) {
    $new_chal .= sprintf("%02x ", $repl->[$i]);
  }
  $chal_p = unpack_hex($new_chal);
  $chal_pack = pack('C' . $length, @$chal_p);
  my $resp = &$hash_func($chal_pack, $code_pack);
  my @resp_p = unpack('C*', $resp);
  $len = scalar(@resp_p) + 2;
  @apdu = (0x00, 0xa3, 0x00, 0x00, $len, 0x7f, scalar(@resp_p), @resp_p);
  $repl = send_apdu(\@apdu);
}

die "no action specified" unless $action;

if($action eq 'change-code') {
  die "No key specified." unless $key;
  my $key_p = unpack_hex($key);
  my $len = scalar(@$key_p) + 2;
  my @apdu = (0x00, 0x03, 0x00, 0x00, $len, $key_tag, $type, scalar(@$key_p), @$key_p);
  my $repl = send_apdu(\@apdu);
  if($repl->[0] != 0x90) {
    die "failed setting code.";
  }
}

if($action eq 'list') {
  my $repl = send_apdu([0x00, $name_list_tag, 0x00, 0x00]);
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
  my @apdu = (0x00, 0x01, 0x00, 0x00, $len, $name_tag, scalar(@name_p), @name_p, $key_tag, $type, $digits, scalar(@$key_p), @$key_p);
  my $repl = send_apdu(\@apdu);
}

if($action eq 'delete') {
  die "No name specified." unless $name;
  my @name_p = unpack("C*", $name);
  my $len = scalar(@name_p) + 2;
  my @apdu = (0x00, 0x02, 0x00, 0x00, $len, $name_tag, scalar(@name_p), @name_p);
  my $repl = send_apdu(\@apdu);
}

if($action eq 'calculate') {
  die "No name specified." unless $name;
  die "No challenge specified." unless $challenge;

  my @name_p = unpack("C*", $name);
  my $chal_p = unpack_hex($challenge);
  my $len = scalar(@name_p) + 2 + scalar(@$chal_p) + 2;
  my @apdu = (0x00, 0xa2, 0x00, 0x01, $len, $name_tag, scalar(@name_p), @name_p, $challenge_tag, scalar(@$chal_p), @$chal_p);
  my $repl = send_apdu(\@apdu);

  die "error on calc" unless $repl->[0] == 0x7d;
  my $offs = 2; # status and length..
  my $code = calc_oath($repl, $offs);
  printf("code is %0${digits}d\n", $code);
}

if($action eq 'calculate-all') {
  die "No challenge specified." unless $challenge;
  my $chal_p = unpack_hex($challenge);
  my $len = scalar(@$chal_p) + 2;
  my @apdu = (0x00, 0xa4, 0x00, 0x01, $len, $challenge_tag, scalar(@$chal_p), @$chal_p);
  my $repl = send_apdu(\@apdu);
  $len = scalar(@$repl);
  my $offs = 0;
  while($offs < $len - 2) {
    die "error on calc all" unless $repl->[$offs++] == 0x7a;
    my $length = get_len($repl, $offs++);
    for(my $i = 0; $i < $length; $i++) {
      print chr($repl->[$offs + $i]);
    }
    $offs += $length;
    die "error on calc all" unless $repl->[$offs++] == 0x7d;
    $length = get_len($repl, $offs++);
    my $code = calc_oath($repl, $offs);
    printf(": %0${digits}d", $code);
    print "\n";
    $offs += $length;
  }
}

sub calc_oath {
  my $repl = shift;
  my $offs = shift;

  my $ref = [@$repl[$offs..($offs + 3)]];

  my $code = unpack("N", pack("C4", @$ref));
  return $code % (10 ** $digits);
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

__END__

=head1 NAME

client.pl - communicate with ykneo-oath

=head1 SYNOPSIS

client.pl [options] [action]

 Options:
  -reader=name    partial reader name to match
  -name=name      name of credential to operate on (valid for put/delete/calculate)
  -key=key        key to operate on (valid for put/change-code)
  -challenge=chal challenge to send (valid for calculate)
  -digits=[1-9]   number of digits of oath code to construct (valid for calculate)
  -type=xx        type of credential (10=HOTP, 20=TOTP, 1=HMAC-SHA1, 2=HMAC-SHA256) (valid for put)
  -code=code      unlock-code to send
  -debug          debug mode (show all APDUs sent)

 Actions:
  -list           list loaded credentials
  -put            put a new credential to key
  -delete         delete a credential
  -calculate      calculate an oath code
  -calculate-all  calculate oath code for all loaded credentials
  -change-code    change unlock-code

 Key, challenge and code take the value as either an ascii string or as a byte
  array like: '6b 61 6b 61 ' (note the trailing space).

=cut
