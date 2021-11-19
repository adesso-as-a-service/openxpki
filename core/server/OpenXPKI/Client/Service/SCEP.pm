package OpenXPKI::Client::Service::SCEP;

use Moose;
use warnings;
use strict;
use Carp;
use English;
use Data::Dumper;
use Log::Log4perl qw(:easy);
use MIME::Base64;
use OpenXPKI::Exception;
use OpenXPKI::Client::Service::Response;

extends 'OpenXPKI::Client::Service::Base';

has transaction_id => (
    is => 'ro',
    isa => 'Str',
    lazy => 1,
    default => sub { return shift->attr()->{transaction_id}; }
);

has message_type => (
    is => 'ro',
    isa => 'Str',
    lazy => 1,
    default => sub {
        return shift->attr()->{message_type};
    }
);

has signer => (
    is => 'ro',
    isa => 'Str',
    lazy => 1,
    default => sub { return shift->attr()->{signer} || ''; }
);

# this can NOT be set via the constructor as we need other attributes
# to finally parse the message. The trigger "reads" attr which then
# triggers the actual parsing which allows us to keep attr read-only
has pkcs7message => (
    is => 'rw',
    isa => 'Str',
    init_arg => undef,
    trigger => sub { shift->attr() }
);

has attr => (
    is => 'ro',
    isa => 'HashRef',
    lazy => 1,
    builder => '__parse_message'
);


sub __parse_message {

    my $self = shift;

    my $pkcs7 = $self->pkcs7message();
    die "Message is not set or empty" unless($pkcs7);
    my $result = {};
    eval {
        $result = $self->backend()->run_command('scep_unwrap_message',{
            message => $pkcs7
        });
    };
    if ($EVAL_ERROR) {
        $self->logger->error("Unable to unwrap message ($EVAL_ERROR)");
        die  "Unable to unwrap message";
    }
    $self->logger->trace(Dumper $result);
    return $result;
}

sub _prepare_result {

    my $self = shift;
    my $workflow = shift;

    return OpenXPKI::Client::Service::Response->new({
        workflow => $workflow,
        result => $workflow->{context}->{cert_identifier},
    });

}

sub generate_pkcs7_response {

    my $self = shift;
    my $response = shift;

    my %params = (
        alias           => $self->attr()->{alias},
        transaction_id  => $self->transaction_id,
        request_nonce   => $self->attr()->{sender_nonce},
        digest_alg      => $self->attr()->{digest_alg},
        enc_alg         => $self->attr()->{enc_alg},
    );

    if ($response->is_pending()) {
        return $self->backend()->run_command('scep_generate_pending_response', \%params);
    }

    if ($response->is_client_error()) {

        my $failInfo = ($response->error == 40001) ? 'badMessageCheck' : 'badRequest';
        return $self->backend()->run_command('scep_generate_failure_response',
            { %params, failinfo => $failInfo });
    }

    if (!$response->is_server_error()) {
        return $self->backend()->run_command('scep_generate_cert_response',
        { %params, (
            identifier  => $response->result,
            signer      => $self->signer,
        )});
    }
    return;

}

around 'build_params' => sub {

    my $orig = shift;
    my $self = shift;

    my $params = $self->$orig(@_);

    return unless($params); # something is wrong

    # nothing special if we are NOT in PKIOperation mode
    return $params unless ($self->operation() eq 'PKIOperation');

    $self->logger->debug('Adding extra params for message type ' . $self->message_type());

    if ($self->message_type() eq 'PKCSReq') {
        # This triggers the build of attr which triggers the unwrap call
        # against the server API and populates the class attributes
        $params->{pkcs10} = $self->attr()->{pkcs10};
        $params->{transaction_id} = $self->transaction_id();
        $params->{signer_cert} = $self->signer();
    } elsif ($self->message_type() eq 'GetCertInitial') {
        $params->{pkcs10} = '';
        $params->{transaction_id} = $self->transaction_id();
        $params->{signer_cert} = $self->signer();
    } elsif ($self->message_type() =~ m{\AGet(Cert|CRL)\z}) {
        $params->{issuer} = $self->attr()->{issuer_serial}->{issuer};
        $params->{serial} = $self->attr()->{issuer_serial}->{serialNumber};
    }

    $self->logger->trace(Dumper $params);

    return $params;
};

1;

__END__;