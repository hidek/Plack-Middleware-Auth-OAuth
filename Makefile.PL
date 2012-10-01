use inc::Module::Install;
name 'Plack-Middleware-Auth-OAuth';
all_from 'lib/Plack/Middleware/Auth/OAuth.pm';

requires 'Plack';
requires 'OAuth::Lite' => 1.27;

tests 't/*.t';
author_tests 'xt';

test_requires 'Test::More';
auto_set_repository;
auto_include;
WriteAll;
