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

    # initialize dns resolver
    my $resolver = Net::DNS::Resolver->new;
    my $timeout = $self->param('timeout') || 30;
    $resolver->udp_timeout( $timeout );
    $resolver->tcp_timeout( $timeout );
    $resolver->retry(1);

    foreach my $value (@cnsans) {
        my $res = validateCNSANs($value, $white_list, $resolver, \@dns_entries_array);
        if ($res) {
            CTX('log')->application()->error("$value does not match with regex $white_list : $res Cannot auto-approve");
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
    my ($value_validate, $white_list_validate, $dns_resolver, $ref_dns_entries_array) = @_;

    if ($value_validate !~ m{$white_list_validate}) {
        CTX('log')->application()->info("Testing for short-dns names.");
        my $reply;
        # check for short-dns
        foreach my $dns_entry (@{$ref_dns_entries_array}){
            my $fqdn = $value_validate.$dns_entry;
            if ($fqdn =~ m{$white_list_validate}) {
                eval { $reply = $resolver->send( $fqdn ); };
                if ($reply && $reply->answer) {
                    CTX('log')->application()->info("Short dns-name $value_validate validated by white-list entry $dns_entry and resolved dns. Auto-Approve successful.");
                }
                return 0;
            }
        }
        # no dns resolve or/and white-list matching
        return 1;
    }
    # no short dns and matches
    return 0;
}

1;

__END__
