package OpenXPKI::Client::UI::Result;

use Moose;
use namespace::autoclean;

# Core modules
use Data::Dumper;
use Digest::SHA qw(sha1_base64);
use MIME::Base64;
use Carp qw( confess );

# CPAN modules
use CGI 4.08 qw( -utf8 );
use HTML::Entities;
use JSON;
use Moose::Util::TypeConstraints;
use Data::UUID;

# Project modules
use OpenXPKI::i18n qw( i18nTokenizer );
use OpenXPKI::Serialization::Simple;


# Attributes set via constructor by OpenXPKI::Client::UI->__load_class()
has req => (
    is => 'ro',
    isa => 'OpenXPKI::Client::UI::Request',
    predicate => 'has_req',
);

has extra => (
    is => 'rw',
    isa => 'HashRef',
    default => sub { return {}; },
);

has _client => (
    is => 'ro',
    isa => 'OpenXPKI::Client::UI',
    init_arg => 'client',
);

# Internal attributes
has _error => (
    is => 'rw',
    isa => 'HashRef|Undef',
);

has _page => (
    is => 'rw',
    isa => 'HashRef|Undef',
    lazy => 1,
    default => undef,
);

has _status => (
    is => 'rw',
    isa => 'HashRef|Undef',
);

has _last_reply => (
    is => 'rw',
    isa => 'HashRef',
);

has _session => (
    is => 'ro',
    isa => 'CGI::Session',
    lazy => 1,
    builder => '_init_session',
);

has _result => (
    is => 'rw',
    isa => 'HashRef|Undef',
    default => sub { {} },
);

has _refresh => (
    is => 'rw',
    isa => 'HashRef|Undef',
);

has redirect => (
    is => 'rw',
    isa => 'Str|HashRef',
    default => '',
);

has serializer => (
    is => 'ro',
    isa => duck_type( [qw( serialize deserialize )] ),
    lazy => 1,
    default => sub { OpenXPKI::Serialization::Simple->new() },
);

has type => (
    is => 'ro',
    isa => 'Str',
    default => 'json',
);

sub BUILD {

    my $self = shift;
    # load global client status if set
    if ($self->_client()->_status()) {
        $self->_status(  $self->_client()->_status() );
    }

}

sub _init_session {

    my $self = shift;
    return $self->_client->session;

}

sub cgi {

    my $self = shift;
    return unless ($self->has_req());
    return $self->req()->cgi;

}

sub add_section {

    my $self = shift;
    my $arg = shift;

    push @{$self->_result()->{main}}, $arg;

    return $self;

}

sub set_status {

    my $self = shift;
    my $message = shift;
    my $level = shift || 'info';
    my $href = shift || '';

    $self->_status({ level => $level, message => $message, href => $href });

    return $self;

}

sub refresh() {

    my $self = shift;
    my $location = shift;
    my $timeout = shift || 60;

    $self->_refresh({ href => $location, timeout => $timeout * 1000 });

    return $self;

}

=head2 send_command

Expects the name of the command as first and the parameter hash as second
argument. Sends the named command to the backend and returned the result.
If the command does not succeed, set_status_from_error_reply is called
and undef is returned. In case the command was a workflow action and the
backend reports a validation error, the error from the validator is set
as status.

If you set a true value for the third parameter, the global status is
B<not> set if an error occurs.

=cut

sub send_command {

    my $self = shift;
    my $command = shift;
    my $params = shift || {};
    my $nostatus = shift || 0;

    $self->logger()->warn("APIv1 command - try to autoconvert");

    my $newparam;
    map { $newparam->{lc($_)} => $params->{$_} } keys %$params;

    my $backend = $self->_client()->backend();
    my $reply = $backend->send_receive_service_msg(
        'COMMAND', { COMMAND => $command, PARAMS => $newparam, API => 2 }
    );
    $self->_last_reply( $reply );

    $self->logger()->trace('send command raw reply: '. Dumper $reply) if $self->logger()->is_trace;

    if ( $reply->{SERVICE_MSG} ne 'COMMAND' ) {
        if (!$nostatus) {
            $self->logger()->error("command $command failed ($reply->{SERVICE_MSG})");
            $self->logger()->trace("command reply ". Dumper $reply) if $self->logger()->is_trace;
            $self->set_status_from_error_reply( $reply );
        }
        return undef;
    }

    return $reply->{PARAMS};

}

=head2 send_command_v2

Copy of send_command but uses the API2 methods.

=cut

sub send_command_v2 {

    my $self = shift;
    my $command = shift;
    my $params = shift || {};
    my $nostatus = shift || 0;

    my $backend = $self->_client()->backend();
    my $reply = $backend->send_receive_service_msg(
        'COMMAND', { COMMAND => $command, PARAMS => $params, API => 2 }
    );
    $self->_last_reply( $reply );

    $self->logger()->trace('send command raw reply: '. Dumper $reply) if $self->logger->is_trace;

    if ( $reply->{SERVICE_MSG} ne 'COMMAND' ) {
        if (!$nostatus) {
            $self->logger()->error("command $command failed ($reply->{SERVICE_MSG})");
            $self->logger()->trace("command reply ". Dumper $reply) if $self->logger()->is_trace;
            $self->set_status_from_error_reply( $reply );
        }
        return undef;
    }

    return $reply->{PARAMS};

}

sub set_status_from_error_reply {

    my $self = shift;
    my $reply = shift;

    my $message = 'I18N_OPENXPKI_UI_UNKNOWN_ERROR';
    if ($reply->{'ERROR'}) {
        # Workflow errors
        if ($reply->{'ERROR'}->{PARAMS} && $reply->{'ERROR'}->{PARAMS}->{__ERROR__}) {
            $message = $reply->{'ERROR'}->{PARAMS}->{__ERROR__};
        } elsif($reply->{'ERROR'}->{LABEL}) {
            $message = $reply->{'ERROR'}->{LABEL};
        }

        $self->logger()->error($message);

        if ($message !~ /I18N_OPENXPKI_UI_/) {
            if ($message =~ /I18N_OPENXPKI_([^\s;]+)/) {
                my $ve = lc($1);
                $ve =~ s/_/ /g;
                $message = "I18N_OPENXPKI_UI_UNKNOWN_ERROR ($ve)";
            } else {
                $message = 'I18N_OPENXPKI_UI_UNKNOWN_ERROR';
            }
        }

    } else {
        $self->logger()->trace(Dumper $reply) if $self->logger()->is_trace;
    }
    $self->_status({ level => 'error', message => $message });

    return $self;
}

=head2 param

Returns a single input parameter, i.e. real CGI parameters and those appended
to the action name using C<!>. Parameters from the action name have precedence.

If the input parameter has got multiple values then only the first value is
returned.

B<Parameters>

=over

=item * I<Str> C<$key> - parameter name to retrieve: a plain parameter name or
a stringified hash (e.g. C<key_param{curve_name}>).

Please note that passing an I<ArrayRef> is no longer supported - please use
L</param_from_fields> instead. Passing C<undef>is also no longer supported.

=back

=cut

sub param {

    my ($self, $key) = @_;

    confess 'param() must be called in scalar context' if wantarray; # die

    my @val = $self->__param($key);
    return $val[0];
}

sub multi_param {

    my ($self, $key) = @_;

    confess 'multi_param() must be called in list context' unless wantarray; # die

    my @val = $self->__param($key);
    return @val;
}

sub __param {

    my ($self, $key) = @_;

    confess "param() / multi_param() expect a single key (string) as argument\n" if (not $key or ref $key); # die

    my @queries = (
        # Try extra parameters appended to action
        sub { return $self->extra->{$key} },
        # Try parameter via request object
        sub { return $self->req->multi_param($key) },
    );

    for my $q (@queries) {
        my @val = $q->();
        return @val if defined $val[0];
    }

    $self->logger->trace("Requested parameter '$key' was not found") if $self->logger->is_trace;
    return;
}

# return a list/hash (tenant => $tenant)_from_env to be directly included
# in any api call. Returns an empty list if tenant is not set
sub __tenant {
    my $self = shift;
    my $tenant = $self->param('_tenant');
    return (tenant => $tenant) if ($tenant);
    return ();
}

sub param_from_fields {

    my ($self, $fields) = @_;

    my $param = {};
    foreach my $item (@{$fields}) {
        my $name = $item->{name};
        if ($name =~ m{ \[\] \z }xms) {
            $self->logger()->warn("Got field name with square brackets $name");
            $name = substr($name,0,-2);
        }
        next if $name =~ m{ \A wf_ }xms;

        my @v_list = $self->multi_param($name);
        my $vv;
        if ($item->{clonable}) {
            $vv = \@v_list;
        } else {
            if ((my $amount = scalar @v_list) > 1) {
                $self->logger->warn(sprintf "Received %s values for non-clonable field '%s'", scalar @v_list, $name);
            }
            $vv = $v_list[0];
        }

        if ($name =~ m{ \A (\w+)\{(\w+)\} \z }xs) {
            $param->{$1} ||= ();
            $param->{$1}->{$2} = $vv;
        } else {
            $param->{$name} = $vv;
        }
    }
    $self->logger()->trace( "params: " . Dumper $param ) if $self->logger->is_trace;
    return $param;
}

=head2 logger

Return the class logger (log4perl ref)

=cut

sub logger {

    my $self = shift;
    return $self->_client()->logger();
}

=head2 render

Assemble the return hash from the internal caches and send the result
to the browser.

=cut
sub render {

    my $self = shift;
    my $output = shift;

    my $result = $self->_result();

    $result->{error} = $self->_error() if $self->_error();


    if ($self->_status()) {
        $result->{status} = $self->_status();
    } elsif ($self->param('_status')) {
        my $status = $self->_session->param(scalar $self->param('_status'));
        if ($status && ref $status eq 'HASH') {
            $self->logger()->debug("Set persisted status " . $status->{message});
            $result->{status} = $status;
        }
    }


    $result->{page} = $self->_page() if $self->_page();
    $result->{refresh} = $self->_refresh() if ($self->_refresh());

    my $json = JSON->new->utf8;
    my $body;

    # page redirect
    my $redirect = $self->redirect;
    my $redirect_url;
    if ($redirect) {
        if (ref $redirect ne 'HASH') {
            $redirect = { goto => $redirect };
        }

        # Persist and append status
        if ($result->{status}) {
            my $uid = $self->__generate_uid();
            $self->__temp_param($uid, $result->{status}, 15);
            $redirect->{goto} .= '!_status!' . $uid;
        }
        $redirect_url = $redirect->{goto};

        $redirect->{session_id} = $self->_session->id;
        $body = $json->encode( $redirect );

    # raw data
    } elsif ($result->{_raw}) {
        $body = i18nTokenizer ( $json->encode($result->{_raw}) );

    # regular response
    } else {
        $result->{session_id} = $self->_session->id;

        # Add message of the day if set and we have a page section
        if ($result->{page} && (my $motd = $self->_session()->param('motd'))) {
             $self->_session()->param('motd', undef);
             $result->{status} = $motd;
        }
        $body = i18nTokenizer ( $json->encode($result) );
    }


    my $cgi = $self->cgi;
    # Return the output into the given pointer
    if ($output && ref $output eq 'SCALAR') {
        $$output = $body;

    } elsif (ref $cgi) {
        if ($cgi->http('HTTP_X-OPENXPKI-Client')) {
            # Start output stream
            print $cgi->header( @main::header );
            print $body;

        } else {
            my $url;
            # redirect to given page
            if ($redirect_url) {
                $url = $redirect_url;
            # redirect to downloads / result pages
            } elsif ($body) {
                $url = $self->__persist_response( { data => $body } );
            }
            # if url does not start with http or slash, prepend baseurl + route name
            if ($url !~ m{\A http|/}x) {
                my $baseurl = $self->_session()->param('baseurl');
                $url = sprintf("%sopenxpki/%s", $baseurl, $url);
            }
            print $cgi->redirect($url);
        }

    } else {
        $self->logger->error("Cannot render result - CGI object not available");
    }

    return $self;
}

=head2 init_fetch

Method to send the result persisted with __persist_response

=cut

sub init_fetch {

    my $self = shift;
    my $arg = shift;

    my $response = $self->param('id');
    my $data = $self->__fetch_response( $response );

    if (!$data) {
        $self->logger()->error('Got empty response');
        $self->redirect('home!welcome');
        return $self;
    }

    $self->logger()->trace('Got response ' . Dumper $data) if $self->logger()->is_trace;

    # support multi-valued responses (persisted as array ref)
    if (ref $data eq 'ARRAY') {
        my $idx = $self->param('idx');
        $self->logger()->debug('Found mulitvalued response, index is  ' . $idx);
        if (!defined $idx || ($idx > scalar @{$data})) {
            die "Invalid index";
        }
        $data = $data->[$idx];
    }

    if (ref $data ne 'HASH') {
        die "Invalid, incomplete or expired fetch statement";
    }

    $data->{mime} = "application/json; charset=UTF-8" unless($data->{mime});

    # Start output stream
    my $cgi = $self->cgi();

    if ($data->{data}) {
        print $cgi->header( @main::header, -type => $data->{mime}, -attachment => $data->{attachment} );
        print $data->{data};
        exit;
    }

    my ($type, $source) = ($data->{source} =~ m{(\w+):(.*)});
    $self->logger()->debug('Fetch source: '.$type.', Key: '.$source );

    if ($type eq 'file') {
        open (my $fh, "<", $source) || die 'Unable to open file';
        print $cgi->header( @main::header, -type => $data->{mime}, -attachment => $data->{attachment} );
        while (my $line = <$fh>) {
            print $line;
        }
        close $fh;
    } elsif ($type eq 'datapool') {
        # todo - catch exceptions/not found
        my $dp = $self->send_command_v2( 'get_data_pool_entry', {
            namespace => 'workflow.download',
            key => $source,
        });
        if (!$dp->{value}) {
            die "Requested data not found/expired";
        }

        print $cgi->header( @main::header, -type => $data->{mime}, -attachment => $data->{attachment} );
        utf8::encode($dp->{value}) if ($data->{mime} =~ /utf-8/i);
        print $dp->{value};

    } elsif ($type eq 'report') {
        # todo - catch exceptions/not found
        my $report = $self->send_command_v2( 'get_report', {
            name => $source,
            format => 'ALL',
        });
        if (!$report) {
            die "Requested data not found/expired";
        }

        print $cgi->header( @main::header, -type => $report->{mime_type}, -attachment => $report->{report_name} );
        print $report->{report_value};

    }

    exit;

}


=head2 _escape ( string )

Replace html entities in string by their encoding

=cut

sub _escape {

    my $self = shift;
    my $arg = shift;
    return encode_entities($arg);

}



=head2 __register_wf_token( wf_info, token )

Generates a new random id and stores the passed workflow info, expects
a wf_info and the token info to store as parameter, returns a hashref
with the definiton of a hidden field which can be directly
pushed onto the field list. wf_info can be undef / empty string.

=cut

sub __register_wf_token {

    my $self = shift;
    my $wf_info = shift;
    my $token = shift;

    if (ref $wf_info) {
        $token->{wf_id} = $wf_info->{workflow}->{id};
        $token->{wf_type} = $wf_info->{workflow}->{type};
        $token->{wf_last_update} = $wf_info->{workflow}->{last_update};
    }
    my $id = $self->__generate_uid();
    $self->logger()->debug('wf token id ' . $id);
    $self->logger()->trace('token info ' . Dumper  $token) if $self->logger()->is_trace;
    $self->_session->param($id, $token);
    return { name => 'wf_token', type => 'hidden', value => $id };
}


=head2 __register_wf_token_initial ( wf_type, token )

Create a token to init a new workflow, expects the name of the workflow
as string and an optional hash to pass as initial parameters to the
create method. Returns the full action target as string.

=cut

sub __register_wf_token_initial {

    my $self = shift;
    my $wf_info = shift;
    my $wf_param = shift || {};

    my $token = {
        wf_type => $wf_info,
        wf_param => $wf_param,
        redirect => 1, # initial create always forces a reload of the page
    };

    my $id = $self->__generate_uid();
    $self->logger()->debug('wf token id ' . $id);
    $self->_session->param($id, $token);
    return  "workflow!index!wf_token!$id";
}



=head2 __fetch_wf_token( wf_token, purge )

Return the hashref stored by __register_wf_token for the given
token id. If purge is set to a true value, the info is purged
from the session context.

=cut
sub __fetch_wf_token {

    my $self = shift;
    my $id = shift;
    my $purge = shift || 0;

    return {} unless $id;

    $self->logger()->debug( "load wf_token " . $id );

    my $token = $self->_session->param($id);
    $self->_session->clear($id) if($purge);
    return $token;

}

=head2 __purge_wf_token( wf_token )

Purge the token info from the session.

=cut
sub __purge_wf_token {

    my $self = shift;
    my $id = shift;

    $self->logger()->debug( "purge wf_token " . $id );
    $self->_session->clear($id);

    return $self;

}

=head2 __persist_response

Persist the current response to retrieve it after a http roundtrip
Used to break out of the JS app for downloads or reroute result pages

=cut

sub __persist_response {

    my $self = shift;
    my $data = shift;
    my $expire = shift;

    $expire = '+5m' unless defined $expire;

    my $id = $self->__generate_uid();
    $self->logger()->debug('persist response ' . $id);

    # Auto Persist - use current result when no data is given
    if (!defined $data) {
        my $out;
        $self->render( \$out );
        $data = { data => $out };
    }

    $self->_session->param('response_'.$id, $data );

    $self->_session->expire('response_'.$id, $expire) if ($expire);

    return  "result!fetch!id!$id";

}


=head2 __fetch_response

Get the data for the persisted response.

=cut

sub __fetch_response {

    my $self = shift;
    my $id = shift;

    $self->logger()->debug('fetch response ' . $id);
    my $response = $self->_session->param('response_'.$id);
    if (!$response) {
        $self->logger()->error( "persisted response with id $id does not exist" );
        return;
    }
    return $response;

}

=head2 __generate_uid

Generate a random uid (base64 encoded with dangerours chars removed)

=cut
sub __generate_uid {

    my $self = shift;
    my $queryid = sha1_base64(time.rand().$$);
    $queryid =~ s{[+/]}{}g;
    return $queryid;
}

=head2 __render_pager

Return a pager definition hash with default settings, requires the query
result hash as argument. Defaults can be overriden passing a hash as second
argument.

=cut
sub __render_pager {

    my $self = shift;
    my $result = shift;
    my $args = shift;

    my $limit = ($args->{limit} * 1); # cast to integer for json
    if (!$limit) { $limit = 50; }
    # Safety rule
    elsif ($limit > 500) {  $limit = 500; }

    my $startat = int($args->{startat});

    if (!$args->{pagesizes}) {
        $args->{pagesizes} = [25,50,100,250,500];
    } elsif (!ref $args->{pagesizes}) {
        $args->{pagesizes} = [ (split /\s*,\s*/, $args->{pagesizes}) ];
    }

    if (!grep (/^$limit$/, @{$args->{pagesizes}}) ) {
        push @{$args->{pagesizes}}, $limit;
        $args->{pagesizes} = [ sort { $a <=> $b } @{$args->{pagesizes}} ];
    }

    if (!$args->{pagersize}) {
        $args->{pagersize} = 20;
    }

    $self->logger()->trace('pager query' . Dumper $args) if $self->logger()->is_trace;

    return {
        startat => $startat,
        limit =>  $limit,
        count => $result->{count} * 1,
        pagesizes => $args->{pagesizes},
        pagersize => $args->{pagersize},
        pagerurl => $result->{'type'}.'!pager!id!'.$result->{id},
        order => $result->{query}->{order} || '',
        reverse => $result->{query}->{reverse} ? 1 : 0,
    }
}


=head2 __temp_param

Get or set a temporary session parameter, the value is auto-destroyed after
it was not being used for a given time period, default is 15 minutes.

=cut

sub __temp_param {

    my $self = shift;
    my $key = shift;
    my $data = shift;
    my $expire = shift;

    # one argument - get request
    if (!defined $data) {
        return $self->_session->param( $key );
    }

    $expire = '+15m' unless defined $expire;
    $self->_session->param($key, $data);
    $self->_session->expire($key, $expire) if ($expire);

    return $self;
}


=head2 __build_attribute_subquery

Expects an attribtue query definition hash (from uicontrol), returns arrayref
to be used as attribute subquery in certificate and workflow search.

=cut
sub __build_attribute_subquery {

    my $self = shift;
    my $attributes = shift;

    if (!$attributes || ref $attributes ne 'ARRAY') {
        return {};
    }

    my $attr;

    foreach my $item (@{$attributes}) {
        my $key = $item->{key};
        my $pattern = $item->{pattern} || '';
        my $operator = uc($item->{operator} || 'IN');
        my $transform = $item->{transform} || '';
        my @val = $self->multi_param($key);

        my @preprocessed;

        while (my $val = shift @val) {
            # embed into search pattern from config
            $val = sprintf($pattern, $val) if ($pattern);

            # replace asterisk and question mark as wildcard for like fields
            if ($operator =~ /LIKE/i) {
                $val =~ s/\*/%/g;
                $val =~ s/\?/_/g;
            }

            if ($transform =~ /lower/) {
                $val = lc($val);
            } elsif ($transform =~ /upper/) {
                $val = uc($val);
            }

            $self->logger()->debug( "Query: $key $operator $val" );
            push @preprocessed, $val;
        }

        if (!@preprocessed) {
            next;
        }

        if ($operator eq 'IN') {
            $attr->{$key} = { '=', \@preprocessed };

        } elsif ($operator eq 'INLIKE' ) {
            $attr->{$key} = { -like => \@preprocessed };
        } else {
            # and'ed together - very tricky syntax...
            my @t = map { { $operator, $_ } } @preprocessed;
            unshift @t, '-and';
            $attr->{$key} = \@t;
        }
    }

    $self->logger()->trace('Attribute subquery ' . Dumper $attr) if $self->logger()->is_trace;

    return $attr;

}

=head2 __build_attribute_preset

Expects an attribtue query definition hash (from uicontrol), returns arrayref
to be used as preset when reloading the search form

=cut
sub __build_attribute_preset {

    my $self = shift;
    my $attributes = shift;

    if (!$attributes || ref $attributes ne 'ARRAY') {
        return [];
    }

    my @attr;

    foreach my $item (@{$attributes}) {
        my $key = $item->{key};
        my @val = $self->multi_param($key);
        while (my $val = shift @val) {
            push @attr,  { key => $key, value => $val };
        }
    }

    return \@attr;

}


=head2 transate_sql_wildcards

Replace "literal" wildcards asterisk and question mark by percent and
underscore for SQL queries.

=cut

sub transate_sql_wildcards  {

    my $self = shift;
    my $val = shift;

    return $val if (ref $val);

    $val =~ s/\*/%/g;
    $val =~ s/\?/_/g;

    return $val;
}

=head2 decrypted_param

Return a decrypted JWT input parameter (whose only allowed type is I<HashRef>).

C<undef> is returned if the parameter does not exist or if it was not encrypted.

B<Parameters>

=over

=item * I<Str> C<$key> - parameter name to retrieve.

=back

=cut

sub decrypted_param {

    my $self = shift;
    my $param_name = shift;

    my $item = $self->param($param_name)
        or return;

    if ($item->{__jwt_key} ne $self->_session->param('jwt_encryption_key')) {
        $self->logger->debug("Parameter '".$param_name."'' was not JWT encrypted");
        return;
    }

    return $item;

}

=head2 make_autocomplete_query

Create the autocomplete config for a UI text field from the given workflow
field configuration C<$wf_field>.

Also returns an additional hidden, to-be-encrypted UI field definition.

Text input fields with autocompletion are configured as follows:

    type: text
    autocomplete:
        action: certificate!autocomplete
        params:
            user:
                param_1: field_name_1
                param_2: field_name_1
            persist:
                query:
                    status: { "-like": "%done" }

Parameters below C<user> are filled from the referenced form fields.

Parameters below C<persist> may contain data structures (I<HashRefs>, I<ArrayRefs>)
as they are backend-encrypted and sent to the client as a JWT token. They can
be considered safe from user manipulation.

B<Parameters>

=over

=item * I<HashRef> C<$wf_field> - workflow field config

=back

=cut

sub make_autocomplete_query {

    my $self = shift;
    my $wf_field = shift;

    return unless $wf_field->{autocomplete};

    # $wf_field = {
    #     type: "text",
    #     autocomplete: {
    #         action: "text!autocomplete",
    #         params: {
    #             user: {
    #                 reference_1: "comment",
    #             },
    #             persist: {
    #                 static_a: "deep",
    #                 sql_query: { "-like": "$key_id:%" },
    #             },
    #         },
    #     },
    # }

    my $p = $wf_field->{autocomplete}->{params} // {};
    my $p_user = $p->{user} // {};
    my $p_persist = $p->{persist} // {};

    my $enc_field_name = Data::UUID->new->create_str; # name for additional input field

    my $ac_query_params = {  # the wf config param from the UI param
        %$p_user,
        __encrypted => $enc_field_name,
    };

    # additional input field with encrypted data (protected from frontend modification)
    my $enc_field = {
        name => $enc_field_name,
        type => 'encrypted',
        value => {
            persistent_params => $p_persist,
            user_param_whitelist => [ sort keys %$p_user ], # allowed in subsequent request from frontend
        },
    };

    return ($ac_query_params, $enc_field)

}

=head2 fetch_autocomplete_params

Uses the C<__encrypted> request parameter to re-assemble the full hash of
autocomplete parameters by decoding the encrypted static values and querying
the whitelisted dynamic values.

B<Parameters>

=over

=item * I<HashRef> C<$input_field> - input field definition

=back

B<Returns> a I<HashRef> of query parameters
=cut

sub fetch_autocomplete_params {

    my $self = shift;

    my $data = $self->decrypted_param('__encrypted')
        or return {};

    my %params = %{ $data->{persistent_params} };
    $params{$_} = $self->param($_) for @{ $data->{user_param_whitelist} };

    $self->logger->trace("Autocomplete params: " . Dumper \%params) if $self->logger->is_trace;

    return \%params;

}


__PACKAGE__->meta->make_immutable;
