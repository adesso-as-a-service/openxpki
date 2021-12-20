package OpenXPKI::Server::Workflow::Condition::CheckAutoApprove;

use strict;
use warnings;
use base qw( OpenXPKI::Server::Workflow::Condition );
use Workflow::Exception qw( condition_error configuration_error );
use OpenXPKI::Server::Context qw( CTX );
use OpenXPKI::Debug;
use English;
use OpenXPKI::Exception;
use OpenXPKI::Serialization::Simple;

sub _evaluate
{
    ##! 1: 'start'
    my ( $self, $workflow ) = @_;
    my $context     = $workflow->context();
    my $ser = OpenXPKI::Serialization::Simple->new;

    my $white_list = $self->param->{whitelist};

    # ^((\*\.)?(([a-z0-9\-])+\.){0,2}((int\.smarthouse\.de|smarthouse\.local|smarthouse-adesso\.de|3as\.local|app3as-cloud\.local|3as-test\.local|example\.com|3as-cloud\.local))\|?)+$
    CTX('log')->application()->info("white_list param: $white_list \n");
    # similar to OpenXPKI::Server::Workflow::Activity::CSR::CheckPolicyDNS

    
    # Load Common Name
    my $dn = OpenXPKI::DN->new( $context->param('cert_subject') );
    my %hash = $dn->get_hashed_content();
    #$cnsans = Set::Scalar->new($hash{CN}[0]);
    my @cnsans = ($hash{CN}[0]);

    # Load SAN

    my $san = $context->param('cert_subject_alt_name');

    if ($san) {
        my $sans_csr = $ser->deserialize( $context->param('cert_subject_alt_name'));
        foreach my $pair (@{$sans_csr}) {
            push(@cnsans, $pair->[1]);
        }
    }
    #@sans = sort(@sans);
    my $print_sans = join(", ", @cnsans);
    CTX('log')->application()->info("Testing if White-List matches with $print_sans");
    
    # Load White-List

    # Read in File
    #my $file = '/etc/openxpki/config.d/whitelist.txt';
    #open my $info, '<', $file or do {
    #    condition_error("Could not open $file: $!");
    #};

    #my $result = 0;
    foreach my $value (@cnsans) {
        my $res;

        $res = ($value !~ m{$white_list}) ? 1: 0;
        if ($res) {
            CTX('log')->application()->info("$value does not match with regex $white_list : $res Cannot auto-approve");
            condition_error('cn or san does not match with regex. Cannot auto-approve');
        }
    }

    # TODO: bricht bei erster line ab mit "condition_error", wenn diese nicht matched. Schmeiße condition_error erst am Ende...
    # TODO: Regex will nicht matchen... Komisch
    #my $result = 0;
    #while( my $line = <$info>) {
    #    chomp($line);
    #    if ($white_list eq $line) {
    #        CTX('log')->application()->info("EQUAL!!!!!!!!!!!!!!!!!!!!!!!!");
    #    }
    #    my $res;
    #    foreach my $value (@cnsans) {
    #        CTX('log')->application()->info("Testing, if $value matches with regex $line");
    #        $res = ($value !~ m{$line}) ? 1: 0;
    #        if ($res) {
    #            CTX('log')->application()->info("$value does not match with regex $line : $res Cannot auto-approve");
    #            condition_error('cn or san does not match with regex. Cannot auto-approve');
    #        }
    #    }
    #}

    #close $info;
    return 1;
}

1;

__END__
