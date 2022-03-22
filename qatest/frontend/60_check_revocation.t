#!/usr/bin/perl

use lib qw(../lib);
use strict;
use warnings;
use JSON;
use English;
use Data::Dumper;
use Log::Log4perl qw(:easy);
use TestCGI;

use Test::More tests => 9;

package main;

my $result;
my $client = TestCGI::factory('democa');

my $crl= do { # slurp
    local $INPUT_RECORD_SEPARATOR;
    open my $HANDLE, '<tmp/crl.txt';
    <$HANDLE>;
};

for my $cert (('entity','entity2','pkiclient')) {

    # Load cert status page using cert identifier
    my $cert_identifier = do { # slurp
        local $INPUT_RECORD_SEPARATOR;
        open my $HANDLE, "<tmp/$cert.id";
        <$HANDLE>;
    };

    diag('Testing '  .$cert . ' / ' .$cert_identifier );

    $result = $client->mock_request({
        'page' => 'certificate!detail!identifier!'.$cert_identifier
    });

    my $serial;
    my $status;

    foreach my $item (@{$result->{main}->[0]->{content}->{data}}) {
        # check database status
        $status = $item->{value}->{value} if ($item->{label} eq 'Status');
        $serial = $item->{value}->[0] if ($item->{label} eq 'Certificate Serial');
    }

    is($status, 'REVOKED');

    diag($serial);
    like( $serial, "/[0-9a-f]+/", 'Got serial');
    ok($crl =~ /\s$serial\s/im, 'Serial found on CRL');

}
