package OpenXPKI::Server::Workflow::Condition::CheckAutoApprove;

use strict;
use warnings;
use base qw( OpenXPKI::Server::Workflow::Condition );
use Workflow::Exception qw( condition_error configuration_error );
use OpenXPKI::Server::Context qw( CTX );
use OpenXPKI::Debug;
use English;
use OpenXPKI::Exception;
use Net::DNS;
use Data::Validate::IP;
use OpenXPKI::Serialization::Simple;
use Socket;

sub _evaluate
{
    my ( $self, $workflow ) = @_;
    my $context     = $workflow->context();
    my $ser = OpenXPKI::Serialization::Simple->new;

    my $white_list = $self->param->{whitelist};

    CTX('log')->application()->info("white_list param: $white_list \n");
    # similar to OpenXPKI::Server::Workflow::Activity::CSR::CheckPolicyDNS

    
    # Load Common Name
    my $dn = OpenXPKI::DN->new( $context->param('cert_subject') );
    my %hash = $dn->get_hashed_content();
    my @cnsans = ($hash{CN}[0]);
    my @ips;

    # Load SANs

    my $san = $context->param('cert_subject_alt_name');

    my $validator = Data::Validate::IP->new;

    if ($san) {
        my $sans_csr = $ser->deserialize( $context->param('cert_subject_alt_name'));
        foreach my $pair (@{$sans_csr}) {
            if ($pair->[0] eq 'DNS') {
                if ($validator->is_ipv4($pair->[1])) {
                    my $debug_ip = $pair->[1];
                    CTX('log')->application()->debug("IP detected: $debug_ip");
                    push(@ips, $pair->[1]);
                }
                else {
                    push(@cnsans, $pair->[1]);
                }
            }
            # ignore 'IP' labeled entries
        }
    }

    my $print_sans = join(", ", @cnsans);
    CTX('log')->application()->info("Testing if White-List matches with $print_sans");


    foreach my $value (@cnsans) {
        my $res = validateCNSANs($value, $white_list, \@cnsans);
        if ($res) {
            condition_error('Validation for DNS SAN entries failed. Cannot auto-approve');
        }
    }

    foreach my $ip (@ips) {
        my $res = validateIPs(\@ips, \@cnsans);
        if ($res) {
            condition_error('Couldnt find any successful dns lookup results. Cannot auto-approve');
        }
    }

    return 1;
}

# checks, if cn or san is in white-list.
# also checks for short-dns entries.
# returns 1, if cn or san not in white-list. If cn or san is a short-dns: returns 1, if no matching fqdn available.
# returns 0, if cn or san in white-list. If cn or san is a short-dns: returns 0 if in white-list and fqdn available.

sub validateCNSANs {
    my ($value_validate, $white_list_validate, $ref_cnsans) = @_;

    if ($value_validate !~ m{$white_list_validate}) {
        CTX('log')->application()->info("Testing for short-dns names for dns $value_validate.");
        # check for short-dns
        if (index($value_validate, ".") == -1) {
            FQDN:
            foreach my $value_ref_cnsans (@{$ref_cnsans}) {
                if (index($value_ref_cnsans, ".") == -1) {
                    next;
                }

                my $first = (split /\./, $value_ref_cnsans)[0];
                if ($value_validate eq $first) {
                    # we can return 0 without checking the fqdn, since auto-approval would then fail at fqdn
                    CTX('log')->application()->info("$value_validate is a short-dns and got validated by fqdn $value_ref_cnsans");
                    return 0;
                }
            }
            # short-dns, but no fqdn
            CTX('log')->application()->info("$value_validate is a short-dns, but no fqdn available : Cannot auto-approve");
            return 1;
        }
        else{
            # no short-dns and no white-list match
            CTX('log')->application()->info("$value_validate does not match with regex $white_list_validate : Cannot auto-approve");
            return 1;
        }
    }

    # fqdn matches whitelist
    return 0;
}

# validates all IP san entries by performing a dns lookup for all DNS san entries.
# parameters:
# ref_ips is the array of all detected IP san entries
# ref_cnsans is the array of all the detected DNS san entries

# returns:
# 1, if for any IP san no DNS san lookup could result in the IP-Adress
# 0, if for all the IP sans, there is at least one successful DNS lookup

sub validateIPs {
    my ($ref_ips, $ref_cnsans) = @_;

    foreach my $ip (@{$ref_ips}) {
        my $result = 1;

        LOOP:
        foreach my $name (@{$ref_cnsans}) {
            # perform dns lookup for value_ref_cnsans
            my @addresses = gethostbyname($name) or next;
            @addresses = map { inet_ntoa($_) } @addresses[4 .. $#addresses];

            if ( grep( /^$ip$/, @addresses)) {
                $result = 0;
            }
        }

        if ($result != 0) {
            CTX('log')->application()->info("Couldn't find any successful dns lookup results for IP SAN adress $ip. Cannot auto-approve");
            return 1;
        }
    }
    return 0;
}

1;

__END__
