package OpenXPKI::Client::UI::Request;

use Moose;
use namespace::autoclean;

# Core modules
use Data::Dumper;
use MIME::Base64;
use Carp qw( confess );

# CPAN modules
use JSON;
use Log::Log4perl;
use Crypt::JWT qw( decode_jwt );
use Moose::Util::TypeConstraints;


has cgi => (
    required => 1,
    is => 'ro',
    isa => duck_type( [qw( param multi_param content_type )] ), # not "isa => 'CGI'" as we use CGIMock in tests
);

has session => (
    required => 1,
    is => 'rw',
    isa => 'CGI::Session',
);

has cache => (
    is => 'rw',
    isa => 'HashRef',
    default => sub { return {}; }
);

has method => (
    is => 'rw',
    isa => 'Str',
    default => 'GET',
);

has logger => (
    is => 'ro',
    isa => 'Log::Log4perl::Logger',
    lazy => 1,
    default => sub { return Log::Log4perl->get_logger; }
);

has _prefix_base64 => (
    is => 'ro',
    isa => 'Str',
    default => '_encoded_base64_',
);

has _prefix_jwt => (
    is => 'ro',
    isa => 'Str',
    default => '_encrypted_jwt_',
);

sub BUILD {

    my $self = shift;

    #
    # Preset all keys in the cache (for JSON data, also set the values)
    #
    my %cache;

    # store keys from CGI params
    my @keys = $self->cgi->param;
    $cache{$_} = undef for @keys;
    do { $self->logger->debug(sprintf('CGI param: %s=%s', $_, join(',', $self->cgi->multi_param($_)))) for $self->cgi->param } if $self->logger->is_debug;

    # store keys and values from JSON POST data
    if (($self->cgi->content_type // '') eq 'application/json') {
        $self->logger->debug('Incoming POST data in JSON format (application/json)');

        my $json = JSON->new->utf8;
        my $data = $json->decode( scalar $self->cgi->param('POSTDATA') );

        # Resolve stringified depth-one-hashes - turn parameters like
        #   key{one} = 34
        #   key{two} = 56
        # into a HashRef
        #   key => { one => 34, two => 56 }
        foreach my $combined_key (keys %$data) {
            if (my ($key, $subkey) = $combined_key =~ m{ \A (\w+)\{(\w+)\} \z }xs) {
                $data->{$key} //= {};
                $data->{$key}->{$subkey} = $data->{$combined_key};
            }
        }

        # wrap Scalars and HashRefs in an ArrayRef as param() expects it (but leave ArrayRefs as is)
        $cache{$_} = (ref $data->{$_} eq 'ARRAY' ? $data->{$_} : [ $data->{$_} ]) for keys %$data;

        $self->logger->debug('JSON param: ' . Dumper $data) if $self->logger->is_debug;

        $self->method('POST');
    }

    # special transformations: insert sanitized keys names in the cache so the
    # check in param() will succeed.
    foreach my $key (keys %cache) {
        # Base64 encoded binary data
        my $prefix_b64 = $self->_prefix_base64;
        if (my ($item) = $key =~ /^$prefix_b64(.*)/) { $cache{$item} = undef; next }

        # JWT encrypted data
        my $prefix_jwt = $self->_prefix_jwt;
        if (my ($item) = $key =~ /^$prefix_jwt(.*)/) { $cache{$item} = undef; next }
    }

    $self->cache( \%cache );

}

sub param {

    my $self = shift;
    my $key = shift;

    confess 'param() must be called in scalar context' if wantarray; # die

    my @values = $self->_param($key); # list context
    return $values[0] if defined $values[0];
    return;
}

sub multi_param {

    my $self = shift;
    my $key = shift;

    confess 'multi_param() must be called in list context' unless wantarray; # die
    my @values = $self->_param($key); # list context
    return @values;
}

sub param_keys {

    my $self = shift;

    # send all keys
    confess 'param_keys() must be called in list context' unless wantarray; # die
    return keys %{$self->cache};
}

sub _param {

    my $self = shift;
    my $key = shift;

    confess "param() / multi_param() expect a single key (string) as argument\n" if (not $key or ref $key); # die

    my $msg = sprintf "Param request for '%s': ", $key;

    # try key without trailing array indicator if it does not exist
    if ($key =~ m{\[\]\z} && !exists $self->cache->{$key}) {
        $key = substr($key,0,-2);
        $msg.= "strip array markers, new key '$key', ";
    }

    # valid key?
    return unless exists $self->cache->{$key};

    # cache miss - query parameter
    unless (defined $self->cache->{$key}) {
        my $cgi = $self->cgi;

        my $prefix_b64 = $self->_prefix_base64;
        my $prefix_jwt = $self->_prefix_jwt;

        my @queries = (
            # Try CGI parameters (and strip whitespaces)
            sub {
                return unless $cgi;
                return map { my $v = $_; $v =~ s/^\s+|\s+$//g; $v } ($cgi->multi_param($key))
            },
            # Try Base64 encoded parameter from JSON input
            sub {
                return map { decode_base64($_) } $self->_get_cache($prefix_b64.$key)
            },
            # Try Base64 encoded CGI parameters
            sub {
                return unless $cgi;
                return map { decode_base64($_) } $cgi->multi_param($prefix_b64.$key)
            },
            # Try JWT encrypted JSON data (may be deep structure when decrypted)
            sub {
                return map { $self->_decrypt_jwt($_) } $self->_get_cache($prefix_jwt.$key)
            },
            # Try JWT encrypted CGI parameters (may be deep structure when decrypted)
            sub {
                return unless $cgi;
                return map { $self->_decrypt_jwt($_) } $cgi->multi_param($prefix_jwt.$key)
            },
        );

        for my $query (@queries) {
            my @values = $query->();
            if (scalar @values) {
                $self->cache->{$key} = \@values;
                last;
            }
        }
        $self->logger->trace($msg . 'not in cache. Query result: (' . join(', ', $self->_get_cache($key)) . ')') if $self->logger->is_trace;
    }
    else {
        $self->logger->trace($msg . 'return from cache');
    }

    return $self->_get_cache($key); # list
}

# Returns a list of values (may be a single value or an empty list)
sub _get_cache {

    my $self = shift;
    my $key = shift;

    return @{ $self->cache->{$key} // [] }

}

sub _decrypt_jwt {

    my $self = shift;
    my $token = shift;

    return unless $token;

    my $jwt_key = $self->session->param('jwt_encryption_key');
    unless ($jwt_key) {
        $self->logger->debug("JWT encrypted parameter received but client session contains no decryption key");
        return;
    }

    my $decrypted = decode_jwt(token => $token, key => $jwt_key);
    unless (ref $decrypted eq 'HASH') {
        $self->logger->error("Decrypted JWT data is not a HashRef but a " . ref $decrypted);
        return;
    }

    $decrypted->{__jwt_key} = $jwt_key; # prove that it originated from JWT encoded data

    return $decrypted;

}

__PACKAGE__->meta->make_immutable;


__END__;

=head1 Name

OpenXPKI::Client::UI::Request

=head1 Description

This class is used to hold the input data received as from the webserver
and provides a transparent interface to the application to retrieve
parameter values regardless which transport format was used.

If the data was POSTed as JSON blob, the parameters are already expanded
with the values in the I<cache> hash. If data was send via a CGI method
(either form-encoded or GET), the I<cache> hash holds the keys and the
value undef and the parameter expansion is done on the first request to
L</param>.

=head1 Methods

=head2 param

Retrieves the value(s) of the named parameter.

The L</param> method will B<not> try to guess the type of the attribute,
the requestor must use L</multi_param> or call C<param> in list context to
retrieve a multi-valued attribute.

As the CGI transport does not provide information on the character of the
attribute, the class always tries to translate items from scalar to list
and vice-versa.

=head2 multi_param

Retrieves the named parameter but enforces list context.
