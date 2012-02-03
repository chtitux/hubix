#!/usr/bin/perl
#
# $Id: hubix.pl 4 2012-02-02 18:14:46Z gomor $
# Original author : http://www.protocol-hacking.org/post/2012/01/29/Hubic%2C-maintenant-vraiment-ubiquitous
# Theophile Helleboid - chtitux
#

package Hubic;
use strict;
use warnings;

use LWP::UserAgent;
use Term::ReadKey;

sub new {
   my $self  = shift;
   my $class = ref($self) || $self;

   my %h     = (
      host => 'ws.ovh.com',
      @_,
   );

   my $ua = LWP::UserAgent->new;
   $ua->agent("hubiC/1.0.9 (Windows NT 6.1; fr_FR; hubix)");
   $h{_ua} = $ua;

   return bless(\%h, $class);
}

sub getWebdavInfo {
   my $self = shift;

   my $id                 = $self->_postNasLogin;
   my $url                = $self->_postGetNas($id);
   my ($login, $password) = $self->_postGetCredentials($id);

   return ($url, $login, $password);
}

sub _postNasLogin {
   my $self = shift;

   my $ua       = $self->{_ua};
   my $host     = $self->{host};
   my $login    = $self->{login};
   my $password = $self->{password};

   # 'POST /cloudnas/r0/ws.dispatcher/nasLogin HTTP/1.1'."\r\n".
   # 'Content-Type: application/x-www-form-urlencoded'."\r\n".
   # 'User-Agent: hubiC/1.0.9 (Windows NT 6.1; fr_FR)'."\r\n".
   # 'Content-Length: 126'."\r\n".
   # 'Connection: Keep-Alive'."\r\n".
   # 'Accept-Encoding: gzip'."\r\n".
   # 'Accept-Language: fr-FR,en,*'."\r\n".
   # 'Host: ws.ovh.com'."\r\n".
   # ''."\r\n".
   # 'session=&params=%7B%20%22email%22%20%3A%20%22<login>%22%2C%20%22password%22%20%3A%20%22<password>%22%20%7D'."\r\n".
   # "\r\n";
   my $req = HTTP::Request->new(
      POST => "https://$host/cloudnas/r0/ws.dispatcher/nasLogin",
   );
   $req->content_type('application/x-www-form-urlencoded');
   $req->content('session=&params={"email":"'.$login.'","password":"'.$password.'"}');

   my $res = $ua->request($req);
   if (! $res->is_success) {
      die("FATAL: postNasLogin() failed:\n[", $res->content, "]\n");
   }

   my $reply = $res->content;
   print "[DEBUG] $reply\n" if $self->{debug};

   (my $id = $reply) =~ s/^.*"\s*id\s*?"\s*?:\s*?"\s*(.*?)\s*".*$/$1/;
   print "[DEBUG] Got ID [$id]\n" if $self->{debug};

   return $id;
}

sub _postGetNas {
   my $self = shift;
   my ($id) = @_;

   my $ua   = $self->{_ua};
   my $host = $self->{host};

   # 'POST /cloudnas/r0/ws.dispatcher/getNas HTTP/1.1'."\r\n".
   # 'Content-Type: application/x-www-form-urlencoded'."\r\n".
   # 'User-Agent: hubiC/1.0.9 (Windows NT 6.1; fr_FR)'."\r\n".
   # 'Content-Length: 54'."\r\n".
   # 'Connection: Keep-Alive'."\r\n".
   # 'Accept-Encoding:gzip'."\r\n".
   # 'Accept-Language: fr-FR,en,*'."\r\n".
   # 'Host: ws.ovh.com'."\r\n".
   # ''."\r\n".
   # 'session=<id>'."\r\n".
   # "\r\n";
   my $req = HTTP::Request->new(
      POST => "https://$host/cloudnas/r0/ws.dispatcher/getNas",
   );
   $req->content_type('application/x-www-form-urlencoded');
   $req->content("session=$id");

   my $res = $ua->request($req);
   if (! $res->is_success) {
      die("FATAL: postGetNas() failed:\n[", $res->content, "]\n");
   }

   my $reply = $res->content;
   print "[DEBUG] $reply\n" if $self->{debug};

   (my $url = $reply) =~ s/^.*"\s*url\s*?"\s*?:\s*?"\s*(.*?)\s*".*$/$1/;
   print "[DEBUG] Got URL [$url]\n" if $self->{debug};

   return $url;
}

sub _postGetCredentials {
   my $self = shift;
   my ($id) = @_;

   my $ua   = $self->{_ua};
   my $host = $self->{host};

   # 'POST /cloudnas/r0/ws.dispatcher/getCredentials HTTP/1.1'."\r\n".
   # 'Content-Type: application/x-www-form-urlencoded'."\r\n".
   # 'User-Agent: hubiC/1.0.9 (Windows NT 6.1; fr_FR)'."\r\n".
   # 'Content-Length: 54'."\r\n".
   # 'Connection: Keep-Alive'."\r\n".
   # 'Accept-Encoding: gzip'."\r\n".
   # 'Accept-Language: fr-FR,en,*'."\r\n".
   # 'Host: ws.ovh.com'."\r\n".
   # ''."\r\n".
   # 'session=<id>'."\r\n".
   # "\r\n";
   my $req = HTTP::Request->new(
      POST => "https://$host/cloudnas/r0/ws.dispatcher/getCredentials",
   );
   $req->content_type('application/x-www-form-urlencoded');
   $req->content("session=$id");

   my $res = $ua->request($req);
   if (! $res->is_success) {
      die("FATAL: postGetCredentials() failed:\n[", $res->content, "]\n");
   }

   my $reply = $res->content;
   print "[DEBUG] $reply\n" if $self->{debug};

   (my $username = $reply) =~ s/^.*"\s*username\s*?"\s*?:\s*?"\s*(.*?)\s*".*$/$1/;
   print "[DEBUG] Got username [$username]\n" if $self->{debug};

   (my $secret = $reply) =~ s/^.*"\s*secret\s*?"\s*?:\s*?"\s*(.*?)\s*".*$/$1/;
   print "[DEBUG] Got secret [$secret]\n" if $self->{debug};

   return ($username, $secret);
}

1;

package main;

use Getopt::Std;
my %opts;
getopts('l:dh', \%opts);

if (!$opts{l} || $opts{h}) {
   die("Usage: $0 -l login [-d] [-h]\n");
}

eval("use Term::ReadKey;");
my $readkey = !$@;
my $password = '';
print "Password:";
if ($readkey) {
   ReadMode('noecho');
}
$password = <>;
if($readkey) {
   ReadMode(0);
}

chomp($password);
print "\n";

my $hubic = Hubic->new(
   login    => $opts{l},
   password => $password,
   debug    => $opts{d},
);
my ($hubicUrl, $hubicLogin, $hubicPassword) = $hubic->getWebdavInfo;

print "URL:      $hubicUrl\n";
print "Login:    $hubicLogin\n";
print "Password: $hubicPassword\n\n";
print "mount -t davfs $hubicUrl /mnt\n";

exit(0);
