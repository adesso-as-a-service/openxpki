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
    my $dns_entries = $self->param->{dns_entries};

    CTX('log')->application()->info("white_list param: $white_list \n");
    # similar to OpenXPKI::Server::Workflow::Activity::CSR::CheckPolicyDNS

    
    # Load Common Name
    my $dn = OpenXPKI::DN->new( $context->param('cert_subject') );
    my %hash = $dn->get_hashed_content();
    #$cnsans = Set::Scalar->new($hash{CN}[0]);
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
    
    #parse dns_entries
    my @dns_entries_array = split /:/, $dns_entries;


    foreach my $value (@cnsans) {
        my $res = validateCNSANs($value, $white_list, \@dns_entries_array);
        if ($res) {
            CTX('log')->application()->info("$value does not match with regex $white_list : $res Cannot auto-approve");
            condition_error('cn or san does not match with regex. Cannot auto-approve');
        }
    }

    return 1;
}

# checks, if value is in white-list.
# also checks for short-dns entries
# returns 1, if value does not match
# returns 0, if value matches

sub validateCNSANs {
    my ($value, $white_list, $ref_dns_entries_array) = @_;

    my @dns_entries_array = @($ref_dns_entries_array);

    if ($value !~ m{$white_list}) {
        # check for short-dns
        foreach my $dns_entry (@dns_entries_array) {
            if ($value.$dns_entry ~ m{$white_list}) {
                return 0;
            }
        }
        return 1;
    }

    return 0;
}

1;

__END__
