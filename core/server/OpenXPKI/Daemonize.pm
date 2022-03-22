package OpenXPKI::Daemonize;
use Moose;

=head1 Name

OpenXPKI::Daemonize - Helper functions to cleanly fork background processes

=cut

# Core modules
use English;

# CPAN modules
use POSIX ();

# Project modules
use OpenXPKI::Debug;
use OpenXPKI::Exception;

has max_fork_redo => (
    is => 'rw',
    isa => 'Int',
    default => 5,
);

has sighup_handler => (
    is => 'rw',
    isa => 'CodeRef',
);

has sigterm_handler => (
    is => 'rw',
    isa => 'CodeRef',
);

has uid => (
    is => 'rw',
    isa => 'Int',
);

has gid => (
    is => 'rw',
    isa => 'Int',
);

has old_sig_set => (
    is => 'rw',
    isa => 'POSIX::SigSet',
    init_arg => undef,
);

=head1 METHODS

=head2 fork_child

Tries to fork a child process.

Return value depends on who returns: parent will get the child PID and child
will get 0.

An exception will be thrown if the fork fails.

B<Note on STDIN, STDOUT, STDERR>

All IO handles will be connected to I</dev/null> with one exception: if C<STDERR>
was already redirected to a file (and is not a terminal) then it is left untouched.
This is to make sure error messages still go to the desired log files.

B<Note on SIGCHLD>

The most compatible way to handle C<SIGCHLD> seems to set it to C<'DEFAULT'>,
letting Perl handle it. This way commands like C<system()> will work properly.

For the child process we set C<$SIG{'CHLD'} = 'DEFAULT'>.

The problem is that child processes will become zombies unless the parent
calls C<waitpid()> to reap them.

For the parent process we set up an own C<SIGCHLD> handler that calls C<waitpid()>
to properly reap child processes without affecting calls to C<system()>.

Obviously due to a bug (L<https://github.com/Perl/perl5/issues/17662>) maybe in
conjunction with our use of L<Net::Server> C<SIGCHLD> handling is not reset when
the parent process exits. That is why in C<DEMOLISH> we explicitely hand over
child reaping to the operating system via C<$SIG{'CHLD'} = 'IGNORE'>.

Also see L<https://perldoc.perl.org/perlipc#Signals>.

=cut
sub fork_child {
    my ($self) = @_;

    # reap child processes while allowing e.g. system() to work properly
    $SIG{'CHLD'} = sub {
        # Reap any child process (-1) that became a zombie.
        # The loop is needed as there would be no second SIGCHLD if another
        # process dies while this handler runs.
        1 while waitpid(-1, POSIX::WNOHANG()) > 0; # do nothing, just reap
    };

    my $pid = $self->_try_fork($self->max_fork_redo);

    # parent process: return on successful fork
    if ($pid > 0) { return $pid }

    #
    # child process
    #

    $SIG{'CHLD'} = 'DEFAULT'; # reset SIGCHLD handler so calls to system() etc. work
    $SIG{'HUP'}  = $self->sighup_handler  if $self->sighup_handler;
    $SIG{'TERM'} = $self->sigterm_handler if $self->sigterm_handler;

    if ($self->gid) {
        POSIX::setgid($self->gid);
    }
    if ($self->uid) {
        POSIX::setuid($self->uid);
        $ENV{USER} = getpwuid($self->uid);
        $ENV{HOME} = ((getpwuid($self->uid))[7]);
    }

    umask 0;
    chdir '/';
    open STDIN,  '<',  '/dev/null';
    open STDOUT, '>',  '/dev/null';
    open STDERR, '>>', '/dev/null' if (-t STDERR); # only touch STDERR if it's not already redirected to a file

    # Re-seed Perl random number generator
    srand(time ^ $PROCESS_ID);

    return $pid;
}

=head2 DEMOLISH

Hand C<SIGCHLD> processing over to operating system (see note on C<SIGCHLD> at
L</fork_child>).

=cut
sub DEMOLISH {
    my $self = shift;
    $SIG{'CHLD'} = 'IGNORE';
}

# "The most paranoid of programmers block signals for a fork to prevent a
# signal handler in the child process being called before Perl can update
# the child's $$ variable, its process id."
# (https://docstore.mik.ua/orelly/perl/cookbook/ch16_21.htm)
sub _block_sigint {
    my ($self) = @_;
    my $sigint = POSIX::SigSet->new(POSIX::SIGINT());
    POSIX::sigprocmask(POSIX::SIG_BLOCK(), $sigint, $self->old_sig_set)
        or OpenXPKI::Exception->throw(
            message => 'Unable to block SIGINT before fork()',
            log => { priority => 'fatal', facility => 'system' }
        );
}

sub _unblock_sigint {
    my ($self) = @_;
    POSIX::sigprocmask(POSIX::SIG_SETMASK(), $self->old_sig_set)
        or OpenXPKI::Exception->throw(
            message => 'Unable to reset old signals after fork()',
            log => { priority => 'fatal', facility => 'system' }
        );
}

sub _try_fork {
    my ($self, $max_tries) = @_;

    for (my $i = 0; $i < $max_tries; $i++) {
        $self->_block_sigint;
        my $pid = fork;
        $self->_unblock_sigint;
        # parent or child: successful fork
        if (defined $pid) { return $pid }

        # parent: unsuccessful fork

        # EAGAIN - fork cannot allocate sufficient memory to copy the parent's
        #          page tables and allocate a task structure for the child.
        # ENOMEM - fork failed to allocate the necessary kernel structures
        #          because memory is tight.
        if ($! != POSIX::EAGAIN() and $! != POSIX::ENOMEM()) {
            OpenXPKI::Exception->throw(
                message => 'fork() failed with an unrecoverable error',
                params => { error => $! },
                log => { priority => 'fatal', facility => 'system' }
            );
        }
        sleep 2;
    }

    OpenXPKI::Exception->throw(
        message => 'fork() failed due to insufficient memory, tried $max_tries times',
        log => { priority => 'fatal', facility => 'system' }
    );
}

__PACKAGE__->meta->make_immutable;
