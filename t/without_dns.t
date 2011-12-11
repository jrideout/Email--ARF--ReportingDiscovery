#!perl

use Test::More;
use Data::Dumper;
use Email::ARF::ReportingDiscovery;

#my $d = new Email::ARF::ReportingDiscovery;
#$d->parse('r=test@examle.com');
#$d->check;
#is $d->report_address, 'test@examle.com';

my $r = Email::ARF::ReportingDiscovery->fetch( domain => 'jacobrideout.net' );
    print Dumper (
        {
            report_address  => $r->report_address,
            report_format   => $r->report_format,
            report_interval => $r->report_interval,
            report_types    => [ $r->report_types ],
            contact_address => $r->contact_address,
            report_policy   => $r->report_policy,
            contact_uri     => $r->contact_uri
        }
    );


done_testing;
