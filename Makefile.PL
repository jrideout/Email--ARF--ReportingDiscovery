
use inc::Module::Install;


name 'Email-ARF-ReportingDiscovery';
all_from 'lib/Email/ARF/ReportingDiscovery.pm';

requires 'Mail::DKIM::DNS'   => '0.38';
test_requires 'Test::More'   => '0.96';

WriteAll;

