
package OpenXPKI::Server::Workflow::Activity::Tools::SearchCertificateList;

use strict;
use base qw( OpenXPKI::Server::Workflow::Activity );

use OpenXPKI::Server::Context qw( CTX );
use OpenXPKI::Exception;
use OpenXPKI::Debug;
use OpenXPKI::DN;
use OpenXPKI::DateTime;
use OpenXPKI::Serialization::Simple;
use Workflow::Exception qw( configuration_error );

use Data::Dumper;

sub execute
{
    my $self       = shift;
    my $workflow   = shift;
    my $context    = $workflow->context();


    my $meta_email = $self->param('meta_email');

    my @param = $self->param();


    my $result = CTX('api2')->search_cert_list(meta_email => $meta_email);
    ##! 64: 'Search returned ' . Dumper $result

    my $target_key = $self->param('target_key') || 'cert_list';

    if (@{$result}) {

        $context->param( $target_key => \@{$result});
        CTX('log')->log("SearchCertificateList result " . Dumper \@{$result});

    } else {
        $context->param( { $target_key => undef } );
    }

    return 1;
}

1;

=head1 NAME

OpenXPKI::Server::Workflow::Activity::Tools::SearchCertificateList

=head1 DESCRIPTION

Search for certificates for a given email address. Returns certain parameters defined in the command "search_cert_list" in the file "search_cert.pm".
Returns SAN's as an array

=head1 Configuration

=head2 Example

 class: OpenXPKI::Server::Workflow::Activity::Tools::SearchCertificateList
    param:
        _map_meta_email: "[% context.requestor_email %]"
        target_key: other_key

=head2 Configuration parameters

=over

=item meta_email

The mail address searched for

=item target_key (optional)

The context variable, the certificate_list is being written. Default is "cert_list"

=back
