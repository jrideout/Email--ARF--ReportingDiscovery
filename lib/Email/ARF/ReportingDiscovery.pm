package Email::ARF::ReportingDiscovery;

## TODO make this Consumer, and add Generator

use 5.006;
use strict;
use warnings;
use Carp;

use Mail::DKIM::DNS;

use base qw/ Mail::DKIM::KeyValueList /;

#use base 'Exporter';
#our @EXPORT_OK = qw( rx_range rx_max );

=head1 NAME

Email::ARF::ReportingDiscovery - Implement draft-ietf-marf-reporting-discovery-01

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

sub fetch {
    my $class  = shift;
    my $waiter = $class->fetch_async(@_);
    my $self   = $waiter->();
    return $self;
}

sub fetch_async {
    my $class = shift;
    my %prms  = @_;

    my $host       = '_report.' . $prms{domain};
    my %callbacks  = %{ $prms{Callbacks} || {} };
    my $on_success = $callbacks{Success} || sub { $_[0] };
    $callbacks{Success} = sub {
        my @resp = @_;
        unless (@resp) {

            # no response => NXDOMAIN
            return $on_success->();
        }

        my $strn;
        foreach my $ans (@resp) {
            next unless $ans->type eq "TXT";
            $strn = join "", $ans->char_str_list;
            last;
        }

        $strn
          or return $on_success->();

        my $self = $class->parse($strn);
        $self->{domain} = $prms{'domain'};

        $self->check;
        return $on_success->($self);
    };

    # perform DNS query
    my $waiter =
      Mail::DKIM::DNS::query_async( $host, "TXT", Callbacks => \%callbacks, );
    return $waiter;
}

sub check {
    my $self = shift;
    die 'report_address (r=) required' unless $self->report_address;
}

sub report_address {
    my $self = shift;
    (@_) and $self->set_tag( "r", shift );
    return $self->get_tag("r");
}

sub report_format {
    my $self = shift;
    (@_) and $self->set_tag( "rf", shift );

    my $rf = $self->get_tag("rf");
    return $rf if defined $rf;
    return 'ARF';    #default
}

sub report_interval {
    my $self = shift;
    (@_) and $self->set_tag( "ri", shift );
    return $self->get_tag("ri");
}

sub report_types {
    my $self = shift;
    (@_) and $self->set_tag( "rt", shift );

    ## todo support arrays and array refs in setter
    my $rt = $self->get_tag("rt");
    return split /,/, $rt;
}

sub contact_address {
    my $self = shift;
    (@_) and $self->set_tag( "re", shift );

    my $rf = $self->get_tag("re");
    return $rf if defined $rf;
    return 'abuse@' . $self->{domain};    #default
}

sub report_policy {
    my $self = shift;
    (@_) and $self->set_tag( "rp", shift );

    my $rf = $self->get_tag("rp");
    return $rf if defined $rf;
    return 'o';                           #default
}

sub contact_uri {
    my $self = shift;
    (@_) and $self->set_tag( "ru", shift );
    return $self->get_tag("ru");
}

1;
