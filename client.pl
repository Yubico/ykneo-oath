#!/usr/bin/perl

# Copyright (c) 2013 Yubico AB
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings;

use Chipcard::PCSC;
use Getopt::Long;
use Pod::Usage;
use Digest::SHA qw(hmac_sha1 hmac_sha256);

my $challenge_length = 8;
my $pw_iterations = 1000;

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
my $time;
my $imf;

my $name_tag = 0x71;
my $name_list_tag = 0x72;
my $key_tag = 0x73;
my $challenge_tag = 0x74;
my $response_tag = 0x75;
my $t_response_tag = 0x76;
my $no_response_tag = 0x77;
my $property_tag = 0x78;
my $version_tag = 0x79;
my $imf_tag = 0x7a;

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
           "reset" => \&set_action,
           "time=s" => \$time,
           "imf=s" => \$imf,
           "help" => \$help);

pod2usage(1) if $help;

my $reader;

my $rContext = Chipcard::PCSC->new;
die ("Can't create the PCSC object: $Chipcard::PCSC::errno\n") unless (defined $rContext);
my @readers = $rContext->ListReaders();
foreach my $read (@readers) {
  if(defined($readerMatch)) {
    unless($read =~ m/.*$readerMatch.*/) {
      print "Skipping reader $read.\n" if $debug;
      next;
    }
  }
  $reader = $read;
  last;
}
die "No reader found." unless $reader;
print "Using reader $reader\n" if $debug;

my $card = Chipcard::PCSC::Card->new($rContext, $reader, $Chipcard::PCSC::SCARD_SHARE_SHARED);
die "Card connection failed." unless $card;

# select applet
my ($sw, $data) = $card->TransmitWithCheck("00 a4 04 00 07 a0 00 00 05 27 21 01", "90 00", $debug);
die "Failed to select applet." unless defined $sw;
my @res = split(' ', $data);
die "unexpexted data: " . hex($res[0]) if hex($res[0]) != $version_tag || hex($res[1]) != 3;
if($debug) {
  my $version = hex($res[2]).'.'.hex($res[3]).'.'.hex($res[4]);
  print "version $version detected.\n";
}
die "unexpected data: " . hex($res[5]) if hex($res[5]) != $name_tag;
my $len = hex($res[6]);
my $id = join(' ', @res[7 .. (6 + $len)]) . " ";
print "id of key is $id.\n" if $debug;
my $id_p = pack('C8', @{unpack_hex($id)});

if(defined($action) && $action eq 'reset') {
  print "This will reset this key permanently, abort now if you don't want that!\n";
  sleep(3);
  $card->TransmitWithCheck("00 04 de ad", "90 00", $debug);
}

my $offs = $len + 7;
if(scalar(@res) > $offs) {
  die "unexpected data: " . hex($res[$offs]) if hex($res[$offs]) != $challenge_tag;
  die "no code provided and key is protected." unless defined($code);
  $offs++;
  my $len = hex($res[$offs]);
  my $chal_p = unpack_hex(join(' ', @res[$offs + 1 .. ($offs + $len)]) . " ");
  my $code_pack = pbkdf2($code, $id_p, $pw_iterations, 16, \&hmac_sha1);
  my $hash_func = \&hmac_sha1; # XXX: figure out when to use sha256
  my $chal_pack = pack('C' . $challenge_length, @$chal_p);
  my $resp = &$hash_func($chal_pack, $code_pack);
  my @resp_p = unpack('C*', $resp);

  my $challenge;
  for(my $i = 0; $i < $challenge_length; $i++) {
    $challenge .= sprintf("%02x ", rand(0xff));
  }
  my $own_chal_p = unpack_hex($challenge);
  $len = scalar(@resp_p) + 2 + scalar(@$own_chal_p) + 2;
  my @apdu = (0x00, 0xa3, 0x00, 0x00, $len, $response_tag, scalar(@resp_p), @resp_p, $challenge_tag, scalar(@$own_chal_p), @$own_chal_p);
  my $repl = send_apdu(\@apdu);

  if($repl->[0] != $response_tag) {
    die "wrong answer from server.. " . $repl->[0];
  }
  my $length = $repl->[1];
  my @answer;
  for(my $i = 2; $i < $length + 2; $i++) {
    push(@answer, $repl->[$i]);
  }
  my $answer_pack = pack('C' . $length, @answer);
  $chal_pack = pack('C' . $challenge_length, @$own_chal_p);
  my $correct = &$hash_func($chal_pack, $code_pack);
  if($correct ne $answer_pack) {
    die "answer does not match expected!";
  }
  print "mutual authentication succeeded.\n" if $debug;
}

die "no action specified" unless $action;

if($action eq 'change-code') {
  die "No key specified." unless $key;
  my $hash_func = \&hmac_sha1; # XXX: figure out when to use sha256
  my $code_pack = pbkdf2($key, $id_p, $pw_iterations, 16, \&hmac_sha1);
  my @code_p = unpack('C*', $code_pack);
  my $len = scalar(@code_p) + 2;

  for(my $i = 0; $i < $challenge_length; $i++) {
    $challenge .= sprintf("%02x ", rand(0xff));
  }
  my $own_chal_p = unpack_hex($challenge);
  $len += $challenge_length + 2;
  my $chal_pack = pack('C' . $challenge_length, @$own_chal_p);
  my $correct = &$hash_func($chal_pack, $code_pack);
  my @correct_p = unpack('C*', $correct);
  $len += scalar(@correct_p) + 2;

  my @apdu = (0x00, 0x03, 0x00, 0x00, $len, $key_tag, scalar(@code_p) + 1, 0x21, @code_p, $challenge_tag, $challenge_length, @$own_chal_p, $response_tag, scalar(@correct_p), @correct_p);
  my $repl = send_apdu(\@apdu);
  if($repl->[0] != 0x90) {
    die "failed setting code.";
  }
}

if($action eq 'list') {
  my $repl = send_apdu([0x00, 0xa1, 0x00, 0x00]);
  my $offs = 0;
  my $len = scalar(@$repl);
  my @output;
  for(my $i = 0; $i < ($len - 2); $i++) {
    push(@output, $repl->[$i]);
  }
  while($repl->[$len - 2] == 97) {
    $repl = send_apdu([0x00, 0xa5, 0x00, 0x00]);
    $len = scalar(@$repl);
    for(my $i = 0; $i < ($len - 2); $i++) {
      push(@output, $repl->[$i]);
    }
  }
  $len = scalar(@output) - 2;
  while($offs < $len) {
    if($output[$offs] != $name_list_tag) {
      die "unknown reply: " . $output[$offs];
    }
    $offs++;
    my $length = get_len(\@output, $offs++);
    printf("%02x : ", $output[$offs++]);
    $length--;
    for(my $i = 0; $i < $length; $i++) {
      print chr($output[$offs + $i]);
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
  my @apdu = (0x00, 0x01, 0x00, 0x00, $len, $name_tag, scalar(@name_p), @name_p, $key_tag, scalar(@$key_p) + 2, hex($type), $digits, @$key_p);
  if($imf) {
    push(@apdu, $imf_tag);
    my $imf_p = unpack_hex($imf);
    my $len = scalar(@$imf_p);
    if($len != 4) {
      die "IMF must be 4 bytes.";
    }
    push(@apdu, $len);
    foreach my $b (@$imf_p) {
      push(@apdu, $b);
    }
    $apdu[4] += $len + 2;
  }
  my $repl = send_apdu(\@apdu);
}

if($action eq 'delete') {
  die "No name specified." unless $name;
  my @name_p = unpack("C*", $name);
  my $len = scalar(@name_p) + 2;
  my @apdu = (0x00, 0x02, 0x00, 0x00, $len, $name_tag, scalar(@name_p), @name_p);
  my $repl = send_apdu(\@apdu);
}

die "Only specify one of time and challenge" if defined($time) && defined($challenge);
if($time) {
  if($time eq 'now') {
    $time = time();
  }
  $time /= 30;
  $time = int($time);
  $challenge = sprintf("000000000%02x", $time);
  $challenge =~ s/([0-9a-fA-F]{2})/$1 /g;
}

if($action eq 'calculate') {
  die "No name specified." unless $name;
  die "No challenge specified." unless $challenge;

  my @name_p = unpack("C*", $name);
  my $chal_p = unpack_hex($challenge);
  my $len = scalar(@name_p) + 2 + scalar(@$chal_p) + 2;
  my @apdu = (0x00, 0xa2, 0x00, 0x01, $len, $name_tag, scalar(@name_p), @name_p, $challenge_tag, scalar(@$chal_p), @$chal_p);
  my $repl = send_apdu(\@apdu);

  die "error on calc" unless $repl->[0] == $t_response_tag;
  my $digits = $repl->[2];
  my $offs = 3; # status and length..
  my $code = calc_oath($repl, $offs, $digits);
  print "code is $code\n";
}

if($action eq 'calculate-all') {
  die "No challenge specified." unless $challenge;
  my $chal_p = unpack_hex($challenge);
  my $len = scalar(@$chal_p) + 2;
  my @apdu = (0x00, 0xa4, 0x00, 0x01, $len, $challenge_tag, scalar(@$chal_p), @$chal_p);
  my $repl = send_apdu(\@apdu);
  $len = scalar(@$repl);
  my @output;
  for(my $i = 0; $i < ($len - 2); $i++) {
    push(@output, $repl->[$i]);
  }
  while($repl->[$len - 2] == 97) {
    @apdu = (0x00, 0xa5, 0x00, 0x00);
    $repl = send_apdu(\@apdu);
    $len = scalar(@$repl);
    for(my $i = 0; $i < ($len - 2); $i++) {
      push(@output, $repl->[$i]);
    }
  }

  $len = scalar(@output);

  my $offs = 0;
  while($offs < $len - 2) {
    die "error on calc all" unless $output[$offs++] == $name_tag;
    my $length = get_len(\@output, $offs++);
    for(my $i = 0; $i < $length; $i++) {
      print chr($output[$offs + $i]);
    }
    $offs += $length;
    if($output[$offs] == $no_response_tag) {
      print(": HOTP\n");
      $offs += 3;
      next;
    }
    die "error on calc all" unless $output[$offs++] == $t_response_tag;
    $length = get_len(\@output, $offs++);
    my $digits = $output[$offs];
    my $code = calc_oath(\@output, $offs + 1, $digits);
    print ": $code";
    print "\n";
    $offs += $length;
  }
}

$card->Disconnect();

sub calc_oath {
  my $repl = shift;
  my $offs = shift;
  my $digits = shift;

  my $ref = [@$repl[$offs..($offs + 3)]];

  my $code = unpack("N", pack("C4", @$ref));
  return sprintf("%0${digits}d", $code % (10 ** $digits));
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
  return;
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

sub pbkdf2
{
  my ($password, $salt, $iter, $keylen, $prf) = @_;
  my ($k, $t, $u, $ui, $i);
  $t = "";
  for ($k = 1; length($t) <  $keylen; $k++) {
    $u = $ui = &$prf($salt.pack('N', $k), $password);
    for ($i = 1; $i < $iter; $i++) {
      $ui = &$prf($ui, $password);
      $u ^= $ui;
    }
    $t .= $u;
  }
  return substr($t, 0, $keylen);
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
  -digits=[1-9]   number of digits of oath code to construct (valid for put)
  -type=xx        type of credential (10=HOTP, 20=TOTP, 1=HMAC-SHA1, 2=HMAC-SHA256) (valid for put/change-code)
  -code=code      unlock-code to send
  -debug          debug mode (show all APDUs sent)
  -time=time      take challenge as time, either now or seconds since epoch (valid for calculate)
  -imf=imf        initial-moving-factor supposed to be 4 bytes (valid for HOTP put)

 Actions:
  -list           list loaded credentials
  -put            put a new credential to key
  -delete         delete a credential
  -calculate      calculate an oath code
  -calculate-all  calculate oath code for all loaded credentials
  -change-code    change unlock-code
  -reset          reset to empty state (will delete all credentials)

 Key and challenge take the value as either an ascii string or as a byte
  array like: '6b 61 6b 61 ' (note the trailing space).

=cut
