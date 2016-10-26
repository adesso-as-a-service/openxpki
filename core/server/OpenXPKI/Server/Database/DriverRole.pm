package OpenXPKI::Server::Database::DriverRole;
use Moose::Role;
use utf8;
=head1 Name

OpenXPKI::Server::Database::DriverRole - Moose role that every database driver has to consume

=cut

# Standardize some connection parameters names for all drivers
has 'name'         => ( is => 'ro', isa => 'Str', required => 1 );
has 'namespace'    => ( is => 'ro', isa => 'Str' );    # = schema
has 'host'         => ( is => 'ro', isa => 'Str' );
has 'port'         => ( is => 'ro', isa => 'Int' );
has 'user'         => ( is => 'ro', isa => 'Str' );
has 'passwd'       => ( is => 'ro', isa => 'Str' );

#
# Methods required in driver classes consuming this role
#
requires 'dbi_driver';         # String: DBI compliant case sensitive driver name
requires 'dbi_dsn';            # String: DSN parameters after "dbi:<driver>:"
requires 'dbi_connect_params'; # HashRef: optional parameters to pass to connect()
requires 'sqlam_params';       # HashRef: optional parameters for SQL::Abstract::More

1;

=head1 Synopsis

    package OpenXPKI::Server::Database::Driver::ExoticDb;
    use Moose;
    with 'OpenXPKI::Server::Database::DriverRole';
    ...

Then e.g. in your database.yaml:

    main:
        type: ExoticDb
        ...

=head1 Description

This class contains the API to interact with the configured OpenXPKI database.

=head1 Attributes

=head2 Constructor parameters

=over

=item * B<name> - Database name (I<Str>, required)

=item * B<namespace> - Schema/namespace that will be added as table prefix in all queries. Could e.g. be used to store multiple OpenXPKI installations in one database (I<Str>, optional)

=item * B<host> - Database host: IP or hostname (I<Str>, optional)

=item * B<port> - Database TCP port (I<Int>, optional)

=item * B<user> - Database username (I<Str>, optional)

=item * B<passwd> - Database password (I<Str>, optional)

=back

=head1 Required methods in the consuming driver class

=head2 dbi_driver

Must return the DBI compliant case sensitive driver name (I<Str>).

=head2 dbi_dsn

Must return the DSN as expected by L<DBI/connect> (I<Str>).

=head2 dbi_connect_params

Must return optional parameters to pass to L<DBI/connect> (I<HashRef>).

=head2 sqlam_params

Must return optional parameters to pass to L<SQL::Abstract::More/new> (I<HashRef>).

=cut
