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
use OpenXPKI::Serialization::Simple;

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

    # Load SANs

    my $san = $context->param('cert_subject_alt_name');

    if ($san) {
        my $sans_csr = $ser->deserialize( $context->param('cert_subject_alt_name'));
        foreach my $pair (@{$sans_csr}) {
            push(@cnsans, $pair->[1]);
        }
    }

    my $print_sans = join(", ", @cnsans);
    CTX('log')->application()->info("Testing if White-List matches with $print_sans");


    foreach my $value (@cnsans) {
        my $res = validateCNSANs($value, $white_list, \@cnsans);
        if ($res) {
            CTX('log')->application()->error("$value does not match with regex $white_list : $res Cannot auto-approve");
            condition_error('cn or san does not match with regex. Cannot auto-approve');
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
        CTX('log')->application()->info("Testing for short-dns names.");
        my $reply;
        # check for short-dns
        if ($value_validate !~ m{^\.}) {
            FQDN:
            foreach my $value_ref_cnsans (@{$ref_cnsans}) {
                if ($value_ref_cnsans !~ m{^\.}) {
                    next FQDN;
                }

                if ($value_validate eq (split /\.\, $value_ref_cnsans)[0]) {
                    # we can return 0 without checking the fqdn, since auto-approval would then fail at fqdn
                    return 0;
                }
            }
            # short-dns, but no fqdn
            return 1;
        }
        else{
            # no short-dns and no white-list match
            return 1;
        }
    }
    # fqdn matches whitelist
    return 0;
}

1;

__END__
